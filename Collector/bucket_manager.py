import logging
import asyncio
from datetime import datetime, timedelta
import sys
import threading
import time
import traceback
from typing import Dict
import uuid
from bucket import Bucket
import os
from config import TZ, config_value, config_size,config_timedelta
import psutil
from storage import add_bucket_info, filter_data_with_duckdb, get_buckets_files, get_indexes, merge_parquet_files_pyarrow, store_parquet_bucket_file_info, get_redis_pool, remove_bucket_info_from_redis
from multiprocessing import Process, RLock
import pyarrow.parquet as pq
from timestamp import smart_strptime,parse_event_times
from fastapi import status

logger = logging.getLogger('uvicorn.error')

SCHEMA_IDX="_schema"
INDEXES_IDX="_indexes"

def get_meta_indexes() -> list[str]:
    """Returns a list of meta indexes."""
    return [INDEXES_IDX, SCHEMA_IDX]


class BucketManager:
    def __init__(self):
        self.buckets: Dict[str, list[Bucket]] = {}
        self.lock = threading.Lock()  # Thread-safe lock for async operations
        self.process_lock = RLock()
        self.seq_numbers = {}
        self.running = True
        self.MAX_BUCKETS = config_value("max_buckets", 5)
        self.MAX_BUCKET_EVENTS = config_value("max_bucket_events", 100000)
        self.BUCKET_START_TIME_DELTA = config_timedelta("bucket_start_time_delta", "10m")
        self.MAX_BUCKET_SIZE = config_size("max_bucket_size", "1GB")
        self.BUCKET_STORE = config_value("bucket_store", None)
        self.IDLE_TIME_THRESHOLD = config_timedelta("bucket_idle_time", "10m")
        self.BUCKET_DURATION_THRESHOLD = config_timedelta("bucket_duration_threshold", "1h")
        self.CLEANUP_INTERVAL = config_timedelta("cleanup_interval", "60s")
        self.COMPACTION_INTERVAL = config_timedelta("compaction_interval", "5m")
        self.COMPACTION_THRESHOLD = config_size("compaction_threshold", "100MB")
        self.COMPACTION_FILE_LIMIT = config_value("compaction_file_limit", 100) # Limit the number of files to compact at once
        logger.info(f"BucketManager initialized with {self.MAX_BUCKETS} max buckets, {self.MAX_BUCKET_SIZE} max bucket size, {self.BUCKET_START_TIME_DELTA} bucket start time delta.")

    async def shutdown(self):
        logger.info("Shutting down BucketManager...")
        self.running = False
        await self.flush_all()
        logger.info("Shutdown BucketManager complete.")

    def get_indexes(self, start_time: datetime = None, end_time: datetime = None):
        """Returns a list of indexes with buckets within the given time window."""
        if start_time is None and end_time is None:
            return list(self.buckets.keys())
        if start_time is None:
            start_time = datetime.min.replace(tzinfo=TZ)
        if end_time is None:
            end_time = datetime.max.replace(tzinfo=TZ)
        indexes = set(get_meta_indexes())
        for index, bucket_list in self.buckets.items():
            for bucket in bucket_list:
                if bucket.is_within_time_window(start_time, end_time):
                    indexes.add(index)
                    break
        return sorted(indexes)

    def get_indexes_info(self, start_time: datetime = None, end_time: datetime = None, available_indexes: list[str] = None):
        """Returns a list of indexes with buckets within the given time window."""
        get_all = start_time is None and end_time is None
        if start_time is None:
            start_time = datetime.min.replace(tzinfo=TZ)
        if end_time is None:
            end_time = datetime.max.replace(tzinfo=TZ)
        indexes = {}
        for index, bucket_list in self.buckets.items():
            if available_indexes is None or index in available_indexes:
                for bucket in bucket_list:
                    if get_all or bucket.is_within_time_window(start_time, end_time):
                        add_bucket_info(index, indexes, 1, bucket.num_events(), bucket.size_in_bytes, bucket.start_time, bucket.end_time)
        return indexes


    async def run_compaction_task(self):
        """Runs compaction in a loop, triggered by the collector."""
        logger.info("✅ Background bucket compaction task started.")
        while self.running:
            logger.debug("Starting compaction check...")
            start_time = time.time()
            await self.compact_files()
            logger.debug(f"Compaction check complete in {time.time() - start_time} seconds. Sleeping for {self.COMPACTION_INTERVAL} seconds.")
            end_time = datetime.now(TZ) + self.COMPACTION_INTERVAL
            while datetime.now(TZ) < end_time and self.running:
                await asyncio.sleep(1)  # Sleep before next check


    async def compact_files(self):
        """Compacts Parquet files if they belong to the same day and exceed the size threshold."""
        logger.info("Checking for files to compact...")

        if not self.BUCKET_STORE:
            logger.error("Bucket store not configured. Skipping compaction.")
            return

        indexes_in_store = get_indexes()

        for index in indexes_in_store:
            if not self.running:
                return
            await self.compact_files_in_index(index)

    async def compact_files_in_index(self, index):
        """Compacts Parquet files in a single index, gethering from the redis info."""
        logger.info(f"Checking for files to compact in {index}...")
        parquet_files = get_buckets_files(index)

        # Group files by date
        files_by_date = self.group_files_by_date(parquet_files)

        for date, files in files_by_date.items():
            # check if any file exists and is greater than the threshold, if so, remove it from the list
            files = [f for f in files if os.path.exists(f) and os.path.getsize(f) < self.COMPACTION_THRESHOLD]

            if len(files) < 2:
                logger.debug(f"Skipping {date}, only {len(files)} files found.")
                continue

            file_partitions = self.partition_files(files)
            # Process each partition
            for partition_idx, partition_files in enumerate(file_partitions):
                if len(partition_files) < 2:
                    logger.debug(f"Skipping partition {partition_idx+1} for {date}, only {len(partition_files)} files found.")
                    continue

                logger.info(f"Compacting partition {partition_idx+1} with {len(partition_files)} files for {date}...")
                await launch_compaction_process(partition_files, date)
                if not self.running:
                    logger.info("Stopping compaction due to shutdown.")
                    return
                await asyncio.sleep(0.001)  # Sleep for a short time to avoid blocking

    def partition_files(self, files):
        # Split files into partitions of COMPACTION_FILE_LIMIT
        # Group files by size to respect both count and size limits
        file_partitions = []
        current_partition = []
        current_size_bytes = 0

        for file_path in files:
            # Read the file's size from ParquetFile metadata
            try:
                parquet_file = pq.ParquetFile(file_path)
                row_groups_size = sum(
                    parquet_file.metadata.row_group(i).total_byte_size
                    for i in range(parquet_file.num_row_groups)
                )

                # Check if adding this file would exceed our partition size or count limit
                if (current_size_bytes + row_groups_size > self.MAX_BUCKET_SIZE or
                    len(current_partition) >= self.COMPACTION_FILE_LIMIT):
                    if current_partition:  # Only add non-empty partitions
                        file_partitions.append(current_partition)
                        current_partition = []
                        current_size_bytes = 0

                # Add file to current partition
                current_partition.append(file_path)
                current_size_bytes += row_groups_size

            except Exception as e:
                logger.warning(f"Error reading metadata for {file_path}: {e}, moving to broken")
                self.move_to_broken(file_path)
                continue

        # Add the last partition if it's not empty
        if current_partition:
            file_partitions.append(current_partition)

        logger.info(f"Merge {len(files)} files into {len(file_partitions)}, respecting max {self.COMPACTION_FILE_LIMIT} files and {self.MAX_BUCKET_SIZE} bytes per partition")
        return file_partitions

    def move_to_broken(self, file_path):
        broken_dir = os.path.join(os.path.dirname(file_path), "broken")
        os.makedirs(broken_dir, exist_ok=True)
        broken_path = os.path.join(broken_dir, os.path.basename(file_path))
        os.rename(file_path, broken_path)
        logger.warning(f"Moved {file_path} to {broken_path}")

    def group_files_by_date(self, parquet_files):
        """Groups files by date based on extracted timestamps."""
        files_by_date = {}
        for file in parquet_files:
            timestamp = extract_timestamp(file)
            date_key = timestamp.strftime("%Y%m%d")  # Group by day
            if date_key not in files_by_date:
                files_by_date[date_key] = []
            files_by_date[date_key].append(file)
        return files_by_date


    async def bucket_cleanup(self):
        """ Asynchronous background task to periodically clean up expired buckets. """
        logger.info("✅ Background bucket cleanup task started.")
        while self.running:
            now = datetime.now(TZ)
            for index, bucket_list in list(self.buckets.items()):
                for bucket in list(bucket_list):
                    # Check if bucket should be removed based on duration threshold, and idle time
                    end_time_threshold = now - self.BUCKET_DURATION_THRESHOLD
                    idle_time_threshold = now - self.IDLE_TIME_THRESHOLD
                    logger.info(f"Checking bucket {bucket.id} for index {index} (end_time:{bucket.end_time}, "+\
                                f"last_event_reception_time:{bucket.last_event_reception_time}, end_time_threshold:{end_time_threshold}, "+\
                                    f"idle_time_threshold:{idle_time_threshold})...")
                    if (bucket is not None \
                        and bucket.end_time < end_time_threshold \
                        and bucket.last_event_reception_time < idle_time_threshold):
                        logger.info(f"Saving and removing expired bucket {bucket.id} for index {index} due to duration threshold and idle time.")
                        await self.save_bucket(bucket.index, bucket)
                        logger.info(f"Bucket {bucket.id} saved and removed.")

            logger.info(f"Cleanup check complete. Sleeping for {self.CLEANUP_INTERVAL} seconds.")
            end_time = datetime.now(TZ) + self.CLEANUP_INTERVAL
            while datetime.now(TZ) < end_time and self.running:
                await asyncio.sleep(1)  # Async sleep (non-blocking)


    async def flush_all(self):
        with self.lock:
            for index, bucket_list in self.buckets.items():
                if index == "_bucket":
                    continue
                bucket_list_copy = bucket_list.copy()
                for bucket in bucket_list_copy:
                    await self.save_bucket(bucket.index, bucket)

            metric_bucket_list = self.buckets.get("_bucket", []).copy()
            for bucket in metric_bucket_list:
                await self.save_bucket(bucket.index, bucket)
        return {"message": "All buckets flushed.", "status_code": status.HTTP_200_OK}

    async def flush_index(self, index):
        if index not in self.buckets:
            return {"message": f"No buckets found for index '{index}'.", "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY}

        with self.lock:
            for bucket in self.buckets[index].copy():
                await self.save_bucket(bucket.index, bucket)
        return {"message": f"All buckets for index '{index}' flushed.", "status_code": status.HTTP_200_OK}


    async def flush_bucket(self, index, bucket_id):
        with self.lock:
            if index in self.buckets:
                for bucket in self.buckets[index].copy():
                    if bucket.id == bucket_id:
                        await self.save_bucket(bucket.index, bucket)
                        return {"message": f"Bucket '{bucket_id}' flushed.", "status_code": status.HTTP_200_OK}
                return {"message": f"No bucket found for index '{index}' with ID '{bucket_id}'.", "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY}
            return {"message": f"No buckets found for index '{index}'.", "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY}


    async def _close_oldest_bucket(self, index):
        oldest_bucket = None
        oldest_time = datetime.now(TZ)

        for bucket in self.buckets[index]:
            if bucket.last_event_reception_time < oldest_time:
                oldest_time = bucket.last_event_reception_time
                oldest_bucket = bucket

        if oldest_bucket:
            logger.debug(f"Closing oldest bucket: {oldest_bucket.index}.")
            await self.save_bucket(oldest_bucket.index, oldest_bucket)

    async def process_array(self, index, metadata : dict[str,str], columns : list[str], array : list[list[any]], events_bytes):
        if len(array) == 0 or len(columns) == 0:
            return

        # Create an unique ID for this array processing
        array_id = uuid.uuid4()
        with self.lock:
            start_time = time.time()
            timefield = metadata.get("timefield", "_time")
            logger.debug(f"{array_id}: Processing {len(array[0])} events for index {index} with timefield {timefield} and columns {columns}")

            if timefield not in columns and "_raw" not in columns:
                logger.error(f"{array_id}: Timefield '{timefield}' and _raw not found in columns: {columns}")
                return
            
            if timefield not in columns and "_raw" in columns:
                logger.debug(f"{array_id}: Timefield '{timefield}' not found in columns: {columns}, but _raw is present. Attempt to retrieve timestamp from _raw.")
                # Attempt to extract time from _raw
                timefield = "_raw"

            timefield_index = columns.index(timefield)

            time_col = parse_event_times(array_id, array[timefield_index], metadata.get("timeformat", None))
            min_time = min(time_col)
            max_time = max(time_col)

            # Add metadata columns if not present
            for k, v in metadata.items():
                if k not in columns:
                    metacol = [v] * len(array[0])
                    columns.append(k)
                    array.append(metacol)

            start_time_find_bucket = time.time()
            if index not in self.buckets:
                self.buckets[index] = []
                self.seq_numbers[index] = 0

            open_bucket = None
            for b in self.buckets[index]:
                if b.is_within_time_window(min_time, max_time) and b.num_events() < self.MAX_BUCKET_EVENTS:
                    open_bucket = b
                    break

            if open_bucket is None:
                open_bucket = Bucket(index, min_time - self.BUCKET_START_TIME_DELTA, max_time, self.seq_numbers[index])
                self.buckets[index].append(open_bucket)
                self.seq_numbers[index] += 1

            find_bucket_elapsed = time.time() - start_time_find_bucket
            logger.debug(f"{array_id}: Time to find bucket: {find_bucket_elapsed:.6f} seconds")

            open_bucket.cpu_usage += (time.time() - start_time)
            open_bucket.add_array(columns,array,events_bytes)

            start_time_close = time.time()
            await self.close_if_needed(index)
            close_elapsed = time.time() - start_time_close
            logger.debug(f"{array_id}: Time to close bucket if needed: {close_elapsed:.6f} seconds")
            logger.debug(f"{array_id}: Processed {len(array[0])} events for index {index} in {time.time() - start_time:.6f} seconds.")

    async def close_if_needed(self, index):
        if index not in self.buckets:
            return

        total_buckets = len(self.buckets[index])
        if total_buckets >= self.MAX_BUCKETS:
            await self._close_oldest_bucket(index)

    async def process_events(self, index : str, events : list[dict], events_bytes : int):
        if len(events) == 0 or self.running == False:
            return

        first_event = events[0]
        event_time = smart_strptime(first_event["_time"])

        if event_time is None:
            logger.error(f"Invalid first_event data: {first_event}")
            return

        last_event = events[-1]
        end_time = smart_strptime(last_event["_time"])
        if end_time is None:
            logger.error(f"Invalid last_event data: {last_event}")
            return

        with self.lock:
            if index not in self.buckets:
                self.buckets[index] = []
                self.seq_numbers[index] = 0

            open_bucket = None
            for b in self.buckets[index]:
                if b.is_within_time_window(event_time, end_time) and b.num_events() < self.MAX_BUCKET_EVENTS:
                    open_bucket = b
                    break

            if open_bucket is None:
                ## TODO: Add support for bucket duration threshold
                open_bucket = Bucket(index, event_time - self.BUCKET_START_TIME_DELTA, end_time, self.seq_numbers[index])
                self.buckets[index].append(open_bucket)
                self.seq_numbers[index] += 1

            open_bucket.add_events(events, events_bytes)
        await self.close_if_needed(index)

    def add_metrics(self, metric_type:str, metric:dict|list):
        if len(metric) == 0:
            return

        if isinstance(metric, list):
            self.add_metrics_array(metric_type, metric)
            return

        index = "_" + metric_type
        metric["_index"] = index
        metric["_source"] = metric_type
        metric["_time"] = datetime.now(TZ)
        metric["_host"] = config_value("host")
        metric["pid"] = os.getpid()
        metric["ppid"] = os.getppid()
        asyncio.create_task(self.process_events(index, [metric], len(str(metric))))

    def add_metrics_array(self, metric_type:str, metrics:list[any]):
        index = "_" + metric_type
        metadata = {
            "timeformat": "datetime",
            "timefield": "_time",
            "_index": index,
            "_source": metric_type,
            "_host": config_value("host"),
            "pid": os.getpid(),
            "ppid": os.getppid()
        }
        _time = datetime.now(TZ)
        columns = list(metrics[0].keys())
        metrics_ary = [[m[col] for m in metrics] for col in columns]
        columns.insert(0,"_time")
        metrics_ary.insert(0,[_time] * len(metrics_ary[0]))

        asyncio.create_task(self.process_array(index, metadata , columns, metrics_ary, len(str(metrics))))

    async def save_bucket(self, index : str, bucket : Bucket):
        if index != "_bucket":
            self.add_metrics("bucket",bucket.get_info())
        self.buckets[index].remove(bucket)
        await bucket.save()
        logger.debug(f"Saved bucket {bucket.id} for index {index} in {bucket.get_full_path()}.")
        return bucket.get_full_path()


    async def save_buckets(self, index, start_time: datetime = None, end_time: datetime = None):
        """Saves buckets within the given time window, returns list of files."""
        logger.debug(f"Saving buckets for index {index} from {start_time} to {end_time}.")
        if index not in self.buckets:
            return []
        if start_time is None:
            start_time = datetime.min.replace(tzinfo=TZ)
        if end_time is None:
            end_time = datetime.max.replace(tzinfo=TZ)

        bucs= [b for b in self.buckets[index] if b.is_within_time_window(start_time, end_time)]

        return await asyncio.gather(*[self.save_bucket(index, b) for b in bucs])


    def get_last_records(self, index):
        if index not in self.buckets:
            logger.debug(f"No buckets found for index '{index}'.")
            return []
        # Retrieve the last 5 records for a given index
        table = filter_data_with_duckdb([b.data for b in self.buckets[index]] , None, limit=5, order="_time DESC")
        records = table.to_pylist()
        return records

bucket_manager = BucketManager()
def get_bucket_manager():
    return bucket_manager

def extract_timestamp(filename):
    """Extracts timestamp from the filename format YYYYMMDDHHMMSS-enddate_something.parquet."""
    base_name = os.path.basename(filename)
    timestamp_part = base_name.split("-")[0]  # Extract timestamp before dash
    return smart_strptime(timestamp_part, "%Y%m%d%H%M%S")


def get_parquet_stats(file_paths):
    """
    Returns a list of dictionaries with simplified keys for
    the number of records, file size, and uncompressed size.
    Also returns a summary with total values.

    Parameters:
    - file_paths (list of str): List of Parquet file paths.

    Returns:
    - Tuple: (list of dicts for each file, dict with total values)
    """
    stats = []
    total_rows = 0
    total_size_mb = 0
    total_raw_size_mb = 0
    broken = []

    for file_path in file_paths:
        # Check if the process is still running, allow for quick exit if many files present
        if not bucket_manager.running:
            break
        try:
            # Get file size on disk (in MB)
            file_size = os.path.getsize(file_path) / (1024 * 1024)

            # Read Parquet file metadata
            parquet_file = pq.ParquetFile(file_path)
            num_records = parquet_file.metadata.num_rows

            # Get uncompressed size (in MB)
            num_row_groups = parquet_file.num_row_groups  # Get total row groups
            uncompressed_size = sum(
                parquet_file.metadata.row_group(i).total_byte_size for i in range(num_row_groups)
            ) / (1024 * 1024)

            # Store results per file
            stats.append({
                "file": file_path,
                "rows": num_records,
                "size_mb": round(file_size, 2),
                "raw_size_mb": round(uncompressed_size, 2),
            })

            # Accumulate totals
            total_rows += num_records
            total_size_mb += file_size
            total_raw_size_mb += uncompressed_size

        except Exception as e:
            broken.append(file_path)
            print(f"Error processing {file_path}: {e}")

    # Create summary
    summary = {
        "total_rows": total_rows,
        "total_size_mb": round(total_size_mb, 2),
        "total_raw_size_mb": round(total_raw_size_mb, 2),
        "broken_files": broken,
    }

    return stats, summary


def create_compacted_file(files, date):
    """Runs in a separate process. Reads multiple Parquet files and writes a single compacted file using DuckDB."""
    moving = False
    try:
        # All files have the same namming schema: {date}-{date}_{optional}{seq}.parquet, we need to get the minimum date and the maximum date to create the compacted file
        min_date = min(extract_timestamp(f.split('-')[0]) for f in files)
        max_date = max(extract_timestamp(f.split('-')[1].split('_')[0]) for f in files)
        # Extract directory from the first file
        bucket_dir = os.path.dirname(files[0])
        compacted_filename = f"{bucket_dir}/{min_date.strftime('%Y%m%d%H%M%S')}-{max_date.strftime('%Y%m%d%H%M%S')}_packed_{datetime.now(TZ).strftime("%Y%m%d%H%M%S")}.parquet"
        tmp_compacted_filename = f"{compacted_filename}.tmp"

        # Get number of records of all files
        _, parquet_summary = get_parquet_stats(files)
        total_records = parquet_summary["total_rows"]
        total_size_mb = parquet_summary["total_size_mb"]
        total_raw_size_mb = parquet_summary["total_raw_size_mb"]
        logger.info(f"Files to compress: {files}, Total Size: {total_size_mb} MB, Total raw size: {total_raw_size_mb} MB, Total number of records: {total_records}")

        broken = parquet_summary.get("broken_files", [])
        good_files = [f for f in files if f not in broken]

        # Use DuckDB to efficiently merge files
        start_time = datetime.now(TZ)
        merge_parquet_files_pyarrow(good_files, tmp_compacted_filename, bucket_manager)
        _, parquet_summary = get_parquet_stats([tmp_compacted_filename])
        total_records = parquet_summary["total_rows"]
        total_size_mb = parquet_summary["total_size_mb"]
        total_raw_size_mb = parquet_summary["total_raw_size_mb"]
        logger.info(f"Compaction completed in {datetime.now(TZ) - start_time} for file {compacted_filename}, Total Size: {total_size_mb} MB, Total raw size: {total_raw_size_mb} MB, Total number of records: {total_records}")

        if not bucket_manager.running:
            logger.info("Stopping compaction due to shutdown.")
            return

        logger.debug("Compaction Before Lock")
        bucket_manager.process_lock.acquire()
        logger.debug("Compaction acquire Lock")
        moving = True
        # Rename the compacted file to the final name
        os.rename(tmp_compacted_filename, compacted_filename)
        asyncio.run(store_parquet_bucket_file_info(compacted_filename, get_redis_pool()))

        logger.info(f"Renamed {tmp_compacted_filename} to {compacted_filename}")
        # Rename old files to .old before deletion
        files_to_delete = []
        for file in files:
            old_filename = f"{file}.old"
            # Check if the file exists before renaming, 
            # it might have been relocated
            if os.path.exists(file):
                os.rename(file, old_filename)
                files_to_delete.append(old_filename)
            remove_bucket_info_from_redis(file, get_redis_pool())
            #logger.info(f"Renamed {file} to {old_filename}")

        # TODO: Uncoment this to delete old files
        # logger.info(f"Deleting old files: {files_to_delete}")
        # Delete old files
        # for file in files_to_delete:
        #     os.remove(file)

    except Exception as e:
        logger.exception(f"Error during compaction: {e}")
    finally:
        if moving:
            bucket_manager.process_lock.release()
        logger.info("Compaction release Lock")


async def launch_compaction_process(files, date):
    """Launches a new process to compact files."""
    p = Process(target=create_compacted_file, args=(files, date))
    p.start()
    logger.debug(f"Compaction process started for {files} on process {p.pid}...")
    timeout = 600 # 10 minutes

    # Wait for the process to finish, with a timeout of 60 seconds
    next_check = datetime.now(TZ) + timedelta(seconds=timeout)
    while p.is_alive() and datetime.now(TZ) < next_check and bucket_manager.running:
        await asyncio.sleep(0.2)

    if p.exitcode is None:
        logger.error(f"Process {p.pid} did not exit within {timeout} seconds, terminating...")

        for thread_id, frame in sys._current_frames().items():
            logger.debug('Stack for thread {}:\n{}'.format(thread_id, ''.join(traceback.format_stack(frame))))
        

        p.terminate()
        await asyncio.sleep(2)  # Wait a little more to ensure process is terminated
        # Process didn't terminate gracefully, try with SIGKILL
        try:
            p.kill()  # Send SIGKILL
            logger.warning(f"Sent SIGKILL to process {p.pid}")

            # Wait a little more to ensure process is terminated
            for _ in range(5):  # Wait up to 5 seconds more
                if not p.is_alive():
                    break
                await asyncio.sleep(1)

            if p.is_alive():
                logger.error(f"Process {p.pid} still alive after SIGKILL! This should not happen.")
            else:
                logger.info(f"Process {p.pid} terminated after SIGKILL")
        except Exception as e:
            logger.error(f"Error killing process {p.pid}: {e}")

    exit_code = p.exitcode
    logger.info(f"Process {p.pid} exited with code: {exit_code}")

async def run_compaction_task(manager : BucketManager):
    """Runs compaction in a loop, triggered by the collector."""
    logger.info("✅ Started bucket compaction task...")
    await manager.run_compaction_task()

async def bucket_cleanup_task(manager : BucketManager):
    """ Asynchronous background task to periodically clean up expired buckets. """
    logger.info("✅ Started bucket cleanup task...")
    await manager.bucket_cleanup()

async def running_sleep(manager : BucketManager, interval : timedelta):
    """Sleep for the given interval while checking if manager is still running."""
    end_time = datetime.now(TZ) + interval
    while datetime.now(TZ) < end_time and manager.running:
        await asyncio.sleep(1)  # Sleep before next check

def ip_port(addr):
    """Returns the IP and port from a tuple."""
    if len(addr) == 1:
        return (addr[0], None)

    if len(addr) == 2:
        return addr
    return (None, None)

def simplify_conn(conn):
    """Returns a dictionary with simplified flat keys for a connection."""
    lip, lport = ip_port(conn.laddr)
    rip, rport = ip_port(conn.raddr)

    return {
        "fd": conn.fd,
        "family": conn.family.name,
        "type": conn.type.name,
        "laddr.ip": lip,
        "local.port": lport,
        "raddr.ip": rip,
        "raddr.port": rport,
        "status": conn.status
    }

def net_connections(connections):
    """Returns a list of dictionaries with simplified flat keys for net_connections."""
    return [simplify_conn(c) for c in connections]

async def cpu_metrics_task(manager : BucketManager):
    """ Asynchronous background task to periodically clean up expired buckets. """
    logger.info("✅ Started cpu metrics task...")
    METRICS_INTERVAL = config_timedelta("metrics_interval")
    while manager.running:
        # Get current process CPU and memory usage
        process = psutil.Process(os.getpid())
        # Add process metrics
        manager.add_metrics("net_connections", net_connections(process.net_connections()))

        # Check if memory_maps method exists before calling it
        try:
            manager.add_metrics("memory_maps", [m._asdict() for m in process.memory_maps()])
        except Exception:
            logger.debug("memory_maps not available on this platform or requires higher privileges")

        manager.add_metrics("open_files", [m._asdict() for m in process.open_files()])
        manager.add_metrics("threads", [t._asdict() for t in process.threads()])
        manager.add_metrics("cpu_times", process.cpu_times()._asdict())
        try:
            manager.add_metrics("io_counters", process.io_counters()._asdict())
        except Exception as e:
            logger.debug("io_counters not available on this platform")

        manager.add_metrics("memory_info", process.memory_info()._asdict())
        manager.add_metrics("process",process.as_dict(attrs=['cpu_percent', 'create_time', 'memory_percent', 'num_threads','pid','ppid','status','username']))

        # Get metrics for every subprocess
        try:
            for child in process.children(recursive=True):
                manager.add_metrics("process",child.as_dict(attrs=['cpu_percent', 'create_time', 'memory_percent', 'num_threads','pid','ppid','status','username']))
        except Exception as e:
            logger.warning(f"Error collecting subprocess metrics: {e}")

        await running_sleep(manager, METRICS_INTERVAL)

import asyncio
from datetime import datetime
import os
from config import TZ, config_size, config_timedelta, config_value
import logging
import pyarrow as pa
import pyarrow.parquet as pq
import time
from storage import _get_redis_bucket_key, _store_bucket_info_into_redis, get_redis_pool
from timestamp import smart_strptime

logger = logging.getLogger('uvicorn.error')
# Convert the bucket time duration from config into pandas Timedelta
bucket_time_duration = config_timedelta("bucket_time_duration", "1h")  # Time duration for each bucket

class Bucket:
    def __init__(self, index, start_time, end_time, seq_number):
        self.bucket_store = config_value("bucket_store", "data")
        self.temp_bucket_store = config_value("temp_bucket_store", "/tmp")
        self.max_bucket_size = config_size("max_bucket_size", "1GB")
        self.index = index
        self.start_time: datetime = start_time
        self.end_time: datetime = max(start_time + bucket_time_duration, end_time)  # Use the duration from config
        self.data = pa.Table.from_pylist([])
        self.seq_number = seq_number
        self.size_in_bytes = 0
        self.last_event_reception_time: datetime = datetime.now(TZ)
        self.cpu_usage = 0
        self.id = f"{self.start_time.strftime('%Y%m%d%H%M%S')}-{self.end_time.strftime('%Y%m%d%H%M%S')}_{self.seq_number}"

        logger.debug(f"Created new bucket: {self.index} ({self.start_time} - {self.end_time})")

    def num_events(self):
        return self.data.num_rows

    def compare_schemas(self, schema1, schema2):
        schema1_fields = set(schema1.names)
        schema2_fields = set(schema2.names)
        missing_schema1 = schema2_fields - schema1_fields
        missing_schema2 = schema1_fields - schema2_fields
        return missing_schema1, missing_schema2

    def add_array(self, columns, array, events_size):
        start_time = time.time()
        if len(columns) == 0 or len(array) == 0:
            logger.warning(f"Attempted to add an empty event list to bucket {self.index}.")
            used_time = time.time() - start_time
            self.cpu_usage += used_time
            return

        new_data = pa.Table.from_arrays(array, names=columns)

        self.data = pa.concat_tables([self.data, new_data], promote_options="default")
        self.size_in_bytes += events_size
        self.last_event_reception_time = datetime.now(TZ)

        used_time = time.time() - start_time
        logger.debug(f"Added {len(array[0])} events to bucket {self.index} in {used_time:.2f}s. Size: {events_size}")
        self.cpu_usage += used_time

    def add_events(self, events, events_size):
        start_time = time.time()
        if len(events) == 0:
            logger.warning(f"Attempted to add an empty event list to bucket {self.index}.")
            return

        new_data = pa.Table.from_pylist(events)

        #missing_new, missing_existing = self.compare_schemas(new_data.schema, self.data.schema)
        #for field in missing_new:
        #    new_data.schema.append(pa.field(field, pa.string()))

        #for field in missing_existing:
        #    self.data.schema.append(pa.field(field, pa.string()))

        try:
            self.data = pa.concat_tables([self.data, new_data], promote_options="default")
        except Exception as e:
            logger.error(f"Sample of self.data: {self.data}")
            logger.error(f"Sample of new_data: {new_data}")
            logger.exception(f"Error concatenating tables for index {self.index}: {e}")
            return

        self.size_in_bytes += events_size
        self.last_event_reception_time = datetime.now(TZ)

        used_time = time.time() - start_time

        if logger.isEnabledFor(logging.DEBUG) and self.index != "_internal":
            logger.debug(f"Added {len(events)} events to bucket {self.index} in {used_time:.2f}s. Size: {events_size}")

        self.cpu_usage += used_time

    def is_within_range(self, timestamp: datetime):
        return self.start_time <= timestamp <= self.end_time

    def is_within_time_window(self, starttime: datetime, endtime: datetime):
        return starttime <= self.end_time and endtime > self.start_time

    def is_full(self):
        return self.size_in_bytes >= self.max_bucket_size

    def get_diretory(self, temp_save: bool = False) -> str:
        if temp_save:
            return os.path.join(self.temp_bucket_store, "tmp_buckets", self.index.casefold())
        return os.path.join(self.bucket_store, self.index.casefold(), "buckets")

    def get_full_path(self, temp_save: bool = False):
        return os.path.join(self.get_diretory(temp_save), f"{self.id}.parquet")

    async def save(self, temp_save: bool = False):
        """
        Save the bucket to disk as a Parquet file.
        Don't use logger here as it's not async-safe when running in an event loop and processing _internal logs.
        """
        if self.data.num_rows == 0:
            print(f"Bucket {self.index} has no valid data. Skipping save.")
            return

        directory = self.get_diretory(temp_save)
        os.makedirs(directory, exist_ok=True)
        os.chmod(directory, 0o775)

        full_path = self.get_full_path(temp_save)
        tmp_path = full_path + ".tmp"
        try:
            # Write the Parquet file in a separate thread
            await asyncio.to_thread(pq.write_table, self.data, tmp_path)
            os.chmod(tmp_path, 0o664)
            os.rename(tmp_path, full_path)
            await self.store_online_bucket_info(get_redis_pool())
            print(f"✅ Bucket {self.index} saved to {full_path}.")
        except Exception as e:
            print(f"❌ Failed to save bucket {self.index}: {e}")

        if not temp_save:
            # Clear data after saving
            self.data.slice(0,0)
            self.size_in_bytes = 0

    def get_info(self):
        count = self.data.num_rows
        return {
            "id": self.id,
            "index": self.index,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "seq_number": self.seq_number,
            "last_event_reception_time": self.last_event_reception_time.isoformat() if self.last_event_reception_time else None,
            "size": self.size_in_bytes,
            "eps": count / self.cpu_usage if self.cpu_usage > 0 else 0,
            "cpu_usage": self.cpu_usage,
            "num_events": count
        }

    async def store_online_bucket_info(self, redis):
        bucket_key = _get_redis_bucket_key(self.index, self.id)
        if not redis.exists(bucket_key):
            await _store_bucket_info_into_redis(bucket_key, self.index, self.id, self.start_time.isoformat(), self.end_time.isoformat(), self.size_in_bytes, self.num_events(), self.get_full_path(), redis)
            logger.debug(f"Stored bucket info: {bucket_key}")
        else:
            logger.debug(f"Bucket info already stored: {bucket_key}")




    def __str__(self):
        return f"Bucket {self.index} ({self.start_time} - {self.end_time})"


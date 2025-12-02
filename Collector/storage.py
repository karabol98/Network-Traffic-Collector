from datetime import datetime
import re
from config import TZ
import pyarrow as pa
import duckdb
import time
import logging
import os
import pyarrow.parquet as pq
from redis import Redis
from timestamp import smart_strptime

BUCKETS_STR= "buckets"
BUCKETS_KEY = f"{BUCKETS_STR}:*"


logger = logging.getLogger('uvicorn.error')

# Initialize Redis connection pool
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
REDIS_PASSWORD = os.getenv("REDIS_PASS", None)

def get_redis_info():
    return f"Redis configuration: HOST={REDIS_HOST}, PORT={REDIS_PORT}, DB={REDIS_DB}, PASSWORD={'****' if REDIS_PASSWORD else 'None'}"


redis_pool = None
verify_counter = 0

def get_redis_pool(retries=2, delay=1):
    global redis_pool
    global verify_counter
    if redis_pool:
        try:
            if verify_counter % 10000 == 0:
                redis_pool.ping()

            verify_counter += 1
            return redis_pool
        except Exception as e:
            logger.warning(f"Existing Redis connection is invalid: {e}")
            redis_pool = None

    for attempt in range(retries):
        try:
            redis_pool = Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB,
                password=REDIS_PASSWORD,
                decode_responses=False,
                socket_timeout=5,
                socket_connect_timeout=5,
                socket_keepalive=True,
                health_check_interval=30,
            )
            # Test the connection
            redis_pool.ping()
            logger.info("Connected to Redis successfully.")
            return redis_pool
        except Exception as e:
            logger.error(f"Failed to connect to Redis (attempt {attempt + 1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                raise


def align_and_merge_tables(tables):
    """
    Aligns the schemas of the given tables and merges them into a single table.
    """
    if not tables:
        logger.debug("No tables to merge.")
        return pa.Table.from_pylist([])

    # Normalize schemas to ensure all tables have the same structure
    unified_schema = tables[0].schema
    aligned_tables = [t.cast(unified_schema) for t in tables]  # Align tables to the first schema
    merged_table = pa.concat_tables(aligned_tables)
    logger.debug(f"Merged {len(tables)} tables.")
    return merged_table


def build_query_conditions(table, filters):
    """
    Build SQL WHERE conditions based on the provided filters.
    """
    conditions = []
    if filters:
        for col, val in filters.items():
            if col not in table.column_names:
                logger.warning(f"Skipping filter: Column '{col}' not found in data.")
                continue

            if isinstance(val, list):
                # Convert list of values into an IN clause, escaping strings properly
                escaped_values = ", ".join([f"'{v.replace("'", "''")}'" for v in val])
                conditions.append(f"{col} IN ({escaped_values})")
            else:
                # Escape string values properly
                safe_val = f"'{val.replace("'", "''")}'" if isinstance(val, str) else val
                conditions.append(f"{col} = {safe_val}")
    return conditions



def filter_data_with_duckdb(tables, filters, limit=None, order=None) -> pa.Table:
    if not tables:
        logger.debug("No tables to filter.")
        return pa.Table.from_pylist([])
    try:
        merge_start = time.time()
        merged_table = align_and_merge_tables(tables)
        logger.debug(f"Merged {len(tables)} tables in {time.time() - merge_start:.2f} seconds.")

        # Return merged data directly if no filters, limit, or order are provided
        if not filters and not limit and not order:
            logger.debug("No filters, limit, or order provided. Returning merged data.")
            return merged_table

        query_conditions = build_query_conditions(merged_table, filters)

        where = ""
        if query_conditions:
            where += "WHERE " + " AND ".join(query_conditions)

        con = duckdb.connect()
        try:
            con.register("df", merged_table)

            # Run the DuckDB query
            sql = f"SELECT * FROM df {where}"
            if order:
                sql += f" ORDER BY {order}"
            if limit:
                sql += f" LIMIT {limit}"
            logger.debug(f"Applying filters: {sql}")
            query_start = time.time()
            arrow_table = con.query(sql).to_arrow_table()
            logger.debug(f"Query data in {time.time() - query_start:.2f} seconds.")
        except Exception:
            logger.exception("Error running DuckDB query")
            arrow_table = pa.Table.from_pylist([])
        finally:
            con.close()
        logger.debug(f"Filtered data in {time.time() - merge_start:.2f} seconds.")

        return arrow_table

    except Exception:
        logger.exception("Error filtering data")
        return pa.Table.from_pylist([])  # Return an empty Table on error

def merge_parquet_files_duckdb(files, tmp_compacted_filename):

    con = duckdb.connect()
    try:
        con.query(f"""
                    COPY (
                        SELECT * FROM read_parquet({files}, union_by_name = true)
                    ) TO '{tmp_compacted_filename}' (FORMAT PARQUET);
                """)
    except Exception as e:
        logger.exception(f"Error Parquet files with DuckDB, removing tmp file: {e}")
        if os.path.exists(tmp_compacted_filename):
            os.remove(tmp_compacted_filename)
    finally:
        con.close()


def collect_field_metadata(tables):
    """
    Collect all field names and their types across all tables.
    
    Returns:
        tuple: (all_field_names, field_types)
    """
    all_field_names = set()
    field_types = {}
    
    for table in tables:
        for field in table.schema:
            field_name = field.name
            all_field_names.add(field_name)
            
            if field_name not in field_types:
                field_types[field_name] = []
            field_types[field_name].append(field.type)
            
    return all_field_names, field_types


# Create a unified schema
def create_unified_schema(tables):
    """
    Create a unified schema for all tables based on field types.
    
    Args:
        tables (list): List of PyArrow tables to concatenate
        
    Returns:
        pa.Schema: A unified schema that can be used for all tables
    """

    # Collect all field names and their types across all tables
    all_field_names, field_types = collect_field_metadata(tables)

    unified_fields = []
    for field_name in sorted(all_field_names):
        types = field_types[field_name]
        unique_types = set(str(t) for t in types)
        
        # If multiple types exist, use string type for this field
        if len(unique_types) > 1:
            unified_fields.append(pa.field(field_name, pa.string()))
        else:
            unified_fields.append(pa.field(field_name, types[0]))
    
    return pa.schema(unified_fields)


# Use PyArrow directly to handle schema compatibility
def reconcile_schemas_and_concat_pyarrow_tables(tables):
    """
    Fix schema compatibility using only PyArrow operations
    Args:
        tables (list): List of PyArrow tables to concatenate
    Returns:
        pa.Table: A single PyArrow table with a unified schema
    """
    if not tables:
        return None
    
    if len(tables) == 1:
        return tables[0]

    # Create a unified schema
    unified_schema = create_unified_schema(tables)
    
    # Create new tables with the unified schema
    new_tables = []
    for table in tables:
        arrays = []
        
        for field in unified_schema:
            field_name = field.name
            target_type = field.type
            
            if field_name in table.column_names:
                col = table[field_name]
                col_type = table.schema.field(field_name).type
                
                # Cast if types don't match
                if str(col_type) != str(target_type):
                    col = col.cast(target_type)
                arrays.append(col)
            else:
                # Create a null column for missing fields
                arrays.append(pa.nulls(len(table), target_type))
        
        new_table = pa.Table.from_arrays(arrays, schema=unified_schema)
        new_tables.append(new_table)
    
    return pa.concat_tables(new_tables)


def handle_different_schemas(merged_table, current_table, regex, e, f) -> pa.Table:
    """
    Handle different schemas when merging tables.
    Args:
        merged_table (pa.Table): The merged table so far
        current_table (pa.Table): The current table being merged
        regex (re.Pattern): The regex pattern to match schema errors
        e (Exception): The exception raised during merging
        f (str): The file path of the current table
    Returns:
        pa.Table: The merged table after reconciling schemas
    """
    if regex.match(str(e)):
        logger.warning(f"Failure on merging file {f}, attempting reconcile: {e}")
        try:
            # Attempt to reconcile schemas and concatenate
            merged_table = reconcile_schemas_and_concat_pyarrow_tables([merged_table, current_table])
        except Exception as e:
            logger.warning(f"Error reconciling schemas for file {f}, relocating: {e}")
            # Attempt to move the corrupted file to a broken folder
            relocate_corrupted_file(f)
    else:
        logger.warning(f"Failure on merging file {f}, relocating: {e}")
        # Attempt to move the corrupted file to a broken folder
        relocate_corrupted_file(f)
    return merged_table


def merge_parquet_files_pyarrow(files, tmp_compacted_filename, manager):
    """
    Merge Parquet files using PyArrow.
    This function reads multiple Parquet files, reconciles their schemas if necessary,
    and writes the merged data to a temporary file.
    It also handles timezone issues and attempts to move corrupted files to a "broken" folder.
    This function is designed to be used in a multi-threaded environment, where the manager
    can control the execution flow.
    Args:
        files (list): List of Parquet file paths
        tmp_compacted_filename (str): Path to the output merged file
    """
    try:
        # logger.debug(f"Compacting: Merging {len(files)} Parquet files with PyArrow.")
        # Read all Parquet files into a list of tables
        merged_table = None
        regex = re.compile(r"Unable to merge: Field .* has incompatible types: ")

        for f in files:
            if not manager.running:
                break
            try:
                # logger.debug(f"Compacting: Reading Parquet file {f}.")
                current_table = pq.read_table(f)
            except Exception as e:
                logger.warning(f"Error reading Parquet file {f}: {e}")
                # Attempt to move the corrupted file to a broken folder
                relocate_corrupted_file(f)
                continue

            if merged_table is None:
                merged_table = current_table
                continue

            try:
                # contat tables one by one
                merged_table = pa.concat_tables([merged_table, current_table], promote_options="default")
            except pa.lib.ArrowInvalid as e:
                merged_table = handle_different_schemas(merged_table, current_table, regex, e, f)
            except Exception as e:
                logger.warning(f"Error concating tables, issue in file {f}, relocating: {e}")
                # Attempt to move the corrupted file to a broken folder
                relocate_corrupted_file(f)
        if not merged_table:
            logger.warning("No valid Parquet files found to merge.")
            return
        # Write the merged table to the temporary file
        # logger.debug(f"Compacting: Read {len(files)} tables from Parquet files.")
        pq.write_table(merged_table, tmp_compacted_filename)
        # logger.debug(f"Compacting: Wrote merged table to {tmp_compacted_filename}.")
    except Exception as e:
        logger.warning(f"Error merging Parquet files with PyArrow: {e}")
        # Handle timezone issues
        handle_timezone_issues([merged_table], tmp_compacted_filename, e)


def handle_timezone_issues_in_table(i, table, tables):
    if "_time" in table.column_names:
        mt = table.schema.field_by_name("_time").type

        if not mt.tz:
            # Convert the timestamp type to include UTC timezone
            fields = []
            for field in table.schema:
                if field.name == "_time":
                    # Create a new timestamp field with UTC timezone
                    new_field = pa.field(field.name, pa.timestamp(field.type.unit, TZ), field.nullable)
                    fields.append(new_field)
                else:
                    fields.append(field)

            new_schema = pa.schema(fields)

            # Cast the table to use the new schema with timezone
            tables[i] = table.cast(new_schema)


def handle_timezone_issues(tables, tmp_compacted_filename, e):
    if "Cannot merge timestamp with timezone and timestamp without timezone" in str(e):
        for i, table in enumerate(tables):
            handle_timezone_issues_in_table(i, table, tables)

        try:
            pq.write_table(pa.concat_tables(tables, promote_options="default"), tmp_compacted_filename)
        except Exception as e:
            logger.exception(f"Error Parquet files with PyArrow, removing tmp file: {e}")
            if os.path.exists(tmp_compacted_filename):
                os.remove(tmp_compacted_filename)
    else:
        logger.exception(f"Error Parquet files with PyArrow, removing tmp file: {e}")
        if os.path.exists(tmp_compacted_filename):
            os.remove(tmp_compacted_filename)


def _get_redis_bucket_key(index, bucket_id):
    return f"{BUCKETS_STR}:{index.casefold()}:{bucket_id}"


async def store_parquet_bucket_file_info(filepath, redis):
    file = os.path.basename(filepath)
    root = os.path.dirname(filepath)
    bucket_id = file.replace(".parquet", "")
    index = root.split("/")[-2]  # Adjusted to get the correct index
    bucket_key = _get_redis_bucket_key(index, bucket_id)
    if not redis.exists(bucket_key):
        logger.debug(f"Storing bucket info: {bucket_key}")
        file_path = os.path.join(root, file)
        full_start_time = time.time()
        metadata_start_time = time.time()

        try:
            metadata = pq.read_metadata(file_path)
        except pa.lib.ArrowInvalid as e:
            logger.error(f"Error reading Parquet {file_path} metadata: {e} - moving to broken folder")
            relocate_corrupted_file(file_path)
            return None

        metadata_time = time.time() - metadata_start_time
        rec_count_start_time = time.time()
        record_count = metadata.num_rows
        rec_count_time = time.time() - rec_count_start_time
        uncompressed_file_size = metadata.row_group(0).total_byte_size
        start_time, end_time_seq = bucket_id.split("-")
        end_time = end_time_seq.split("_")[0]
        try:
            start_time = smart_strptime(start_time, '%Y%m%d%H%M%S').isoformat()
            end_time = smart_strptime(end_time, '%Y%m%d%H%M%S').isoformat()
        except Exception as e:
            logger.error(f"Error bucket times {start_time} - {end_time}: {e}")
            relocate_corrupted_file(file_path)
            return None
        store_start_time = time.time()
        await _store_bucket_info_into_redis(bucket_key, index, bucket_id, start_time, end_time, uncompressed_file_size, record_count, file_path, redis)
        store_time = time.time() - store_start_time
        full_time = time.time() - full_start_time
        logger.debug(f"Stored bucket info: {bucket_key}, metadata_time={metadata_time:.2f}s, rec_count_time={rec_count_time:.2f}s, store_time={store_time:.2f}s, full_time={full_time:.2f}s")
    else:
        logger.debug(f"Bucket info already stored: {bucket_key}")

    return bucket_key

def relocate_corrupted_file(file_path):
    root = os.path.dirname(file_path)
    file = os.path.basename(file_path)
    broken_folder = os.path.join(root, "broken")
            # Ensure broken directory exists
    os.makedirs(broken_folder, exist_ok=True)
            # Move the file to broken folder
    broken_path = os.path.join(broken_folder, file)
    try:
        os.rename(file_path, broken_path)
        logger.warning(f"Moved broken file {file_path} to {broken_path}")
    except Exception as move_err:
        logger.error(f"Failed to move broken file {file_path}: {move_err}")


async def _store_bucket_info_into_redis(bucket_key, index, bucket_id, start_time, end_time, uncompressed_file_size, record_count, file_location, redis):
    redis.hmset(bucket_key, {
        "index": index.casefold(),
        "bucket_id": bucket_id,
        "start_time": start_time,
        "end_time": end_time,
        "uncompressed_file_size": uncompressed_file_size,
        "record_count": record_count,
        "file_location": file_location
    })


def remove_bucket_info_from_redis(filename, redis):
    bucket_key = _get_redis_bucket_key(filename.split("/")[-3], filename.split("/")[-1].replace(".parquet", ""))
    if redis.exists(bucket_key):
        redis.delete(bucket_key)
        logger.debug(f"Removed bucket info: {bucket_key}")
    else:
        logger.debug(f"Bucket info not found: {bucket_key}")

async def store_parquet_buckets_info(bucket_path):
    redis = get_redis_pool()
    existing_keys = set(key.decode('utf-8') if isinstance(key, bytes) else key for key in redis.keys(BUCKETS_KEY))

    found_keys = set()

    for root, _, files in os.walk(bucket_path):
        for file in files:
            if re.match(rf"{bucket_path}/[^/]*/{BUCKETS_STR}/(?!broken/).*\.parquet$", os.path.join(root, file)):
                key = await store_parquet_bucket_file_info(os.path.join(root, file), redis)
                if key:
                    found_keys.add(key)


    # Remove keys that are in Redis but no longer exist in the filesystem
    keys_to_remove = existing_keys - found_keys
    for key in keys_to_remove:
        if redis.exists(key):
            redis.delete(key)
            logger.debug(f"Removed stale bucket info: {key}")


def _bucket_info_within_time_range(bucket_info, start_time, end_time):
    bucket_start = smart_strptime(bucket_info[b"start_time"].decode("utf-8"))
    bucket_end = smart_strptime(bucket_info[b"end_time"].decode("utf-8"))
    result = bucket_start <= end_time and bucket_end >= start_time
    return result

def get_buckets_info(index: str | None = None, start_time: datetime = None, end_time: datetime = None):
    redis = get_redis_pool()
    if not start_time:
        start_time = datetime.min.replace(tzinfo=TZ)
    if not end_time:
        end_time = datetime.max.replace(tzinfo=TZ)
    bucket_key = f"{BUCKETS_STR}:{index}:*" if index else BUCKETS_KEY
    bucket_keys = redis.keys(bucket_key)
    buckets_info = []

    # Use pipeline to batch Redis operations and reduce network round-trips
    pipe = redis.pipeline()
    for bucket_key in bucket_keys:
        pipe.hgetall(bucket_key)
    
    # Execute all commands in a single round-trip
    bucket_infos = pipe.execute()

    for bucket_info in bucket_infos:
        if bucket_info:
            if _bucket_info_within_time_range(bucket_info, start_time, end_time):
                buckets_info.append(bucket_info)
    return buckets_info

def get_buckets_files(index: str = None, start_time: datetime = None, end_time: datetime = None):
    buckets_info = get_buckets_info(index, start_time, end_time)
    files = []
    for bucket in buckets_info:
        file_location = bucket[b"file_location"].decode("utf-8")
        if int(bucket[b"record_count"].decode("utf-8")) > 0:
            if os.path.exists(file_location):
                files.append(file_location)
            else:
                remove_bucket_info_from_redis(file_location, get_redis_pool())
                logger.warning(f"Bucket file frm redis not found, removed from redis: {file_location}")

    return files



def get_indexes(start_time: datetime = None, end_time: datetime = None):
    redis = get_redis_pool()
    bucket_keys = redis.keys(BUCKETS_KEY)
    if start_time is None and end_time is None:
        return sorted(set([key.split(b":")[1].decode("utf-8") for key in bucket_keys]))
    if not start_time:
        start_time = datetime.min.replace(tzinfo=TZ)
    if not end_time:
        end_time = datetime.max.replace(tzinfo=TZ)
    indexes = set()

    # Use pipeline to batch Redis operations and reduce network round-trips
    pipe = redis.pipeline()
    for bucket_key in bucket_keys:
        pipe.hgetall(bucket_key)
    
    # Execute all commands in a single round-trip
    bucket_infos = pipe.execute()

    for bucket_info in bucket_infos:
        if bucket_info:
            if _bucket_info_within_time_range(bucket_info, start_time, end_time):
                indexes.add(bucket_info[b"index"].decode("utf-8"))
    return sorted(indexes)


def add_bucket_info(index:str, idx_info: dict, num_buckets: int, events: int, size_in_bytes: int, start_time: datetime, end_time: datetime):
    """
    Add bucket information to the index info dictionary.
    """
    if index not in idx_info:
        idx_info[index] = {"index": index, "buckets": num_buckets, "record_count": events, "size_in_bytes": size_in_bytes, "start_time": start_time, "end_time": end_time}
    else:
        idx_info[index]["buckets"] += num_buckets
        idx_info[index]["record_count"] += events
        idx_info[index]["size_in_bytes"] += size_in_bytes
        idx_info[index]["start_time"] = min(idx_info[index].get("start_time", end_time), start_time)
        idx_info[index]["end_time"] = max(idx_info[index].get("end_time", start_time), end_time)

def get_indexes_info(start_time: datetime = None, end_time: datetime = None, available_indexes: list[str] = None) -> dict:
    """
    Get information about all indexes and their buckets within the specified time range.
    If no time range is provided, all indexes and buckets are returned.
    Information includes the number of buckets, total record count, total uncompressed file size and time range.
    """
    redis = get_redis_pool()
    bucket_keys = redis.keys(BUCKETS_KEY)
    get_all = start_time is None and end_time is None
    if not start_time:
        start_time = datetime.min.replace(tzinfo=TZ)
    if not end_time:
        end_time = datetime.max.replace(tzinfo=TZ)
    indexes = {}

    # Use pipeline to batch Redis operations and reduce network round-trips
    pipe = redis.pipeline()
    for bucket_key in bucket_keys:
        pipe.hgetall(bucket_key)
    
    # Execute all commands in a single round-trip
    bucket_infos = pipe.execute()

    for bucket_info in bucket_infos:
        if bucket_info:
            if get_all or _bucket_info_within_time_range(bucket_info, start_time, end_time):
                index = bucket_info[b"index"].decode("utf-8")
                if available_indexes is None or index in available_indexes:
                    add_bucket_info(index, indexes, 1, int(bucket_info[b"record_count"].decode("utf-8")), int(bucket_info[b"uncompressed_file_size"].decode("utf-8")), smart_strptime(bucket_info[b"start_time"].decode("utf-8")), smart_strptime(bucket_info[b"end_time"].decode("utf-8")))
    return indexes


def count_records_in_parquet_files_from_files(files):
    total_records = 0
    start = time.time()
    for file in files:
        # Read the Parquet file metadata
        parquet_file = pq.ParquetFile(file)
        # Get the number of rows (records) in the file
        total_records += parquet_file.metadata.num_rows
    logger.debug(f"Counted {total_records} records in {time.time() - start:.2f} seconds (files).")
    return total_records



def count_records_in_parquet_files_from_redis(files):
    start = time.time()
    total_records = 0
    redis = get_redis_pool()
    
    # Use pipeline to batch Redis operations and reduce network round-trips
    pipe = redis.pipeline()
    for file_path in files:
        file = os.path.basename(file_path)
        root = os.path.dirname(file_path)
        bucket_id = file.replace(".parquet", "")
        index = root.split("/")[-2]  # Get the index from path
        bucket_key = _get_redis_bucket_key(index, bucket_id)
        pipe.hgetall(bucket_key)
    
    # Execute all commands in a single round-trip
    bucket_infos = pipe.execute()
    
    for bucket_info in bucket_infos:
        if bucket_info and b"record_count" in bucket_info:
            try:
                total_records += int(bucket_info[b"record_count"].decode("utf-8"))
            except (ValueError, TypeError) as e:
                logger.warning(f"Error processing record count: {e}")
    
    logger.debug(f"Counted {total_records} records in {time.time() - start:.2f} seconds (redis).")
    return total_records


def merge_indexes_info(file_idx_info: dict, mem_idx_info: dict) -> dict:
    """
    Merge indexes information from file and memory sources.
    """
    indexes = {}
    for index, info in file_idx_info.items():
        indexes[index] = info.copy()
    for index, info in mem_idx_info.items():
        add_bucket_info(index, indexes, info["buckets"], info["record_count"], info["size_in_bytes"], info["start_time"], info["end_time"])
    return indexes


def get_all_indexes_info(manager, start_timestamp: datetime = None, end_timestamp: datetime = None, available_indexes: list[str] = None) -> list:
    return list(merge_indexes_info(manager.get_indexes_info(start_timestamp, end_timestamp, available_indexes), get_indexes_info(start_timestamp, end_timestamp, available_indexes)).values())


def get_all_indexes_pyarrow(manager, start_timestamp: datetime = None, end_timestamp: datetime = None, available_indexes: list[str] = None) -> pa.Table:
    return convert_bucket_info_list_to_pyarrow(get_all_indexes_info(manager, start_timestamp, end_timestamp, available_indexes))


def convert_bucket_info_list_to_pyarrow(bucket_info_list: list) -> pa.Table:
    """
    Convert bucket info stored in Redis to a PyArrow Table.
    """
    if not bucket_info_list:
        return pa.Table.from_pylist([])
    columns = {
        "index": [],
        "buckets": [],
        "start_time": [],
        "end_time": [],
        "record_count": []
    }
    for bucket_info in bucket_info_list:
        columns["index"].append(bucket_info["index"])
        columns["buckets"].append(bucket_info["buckets"])
        columns["record_count"].append(bucket_info["record_count"])
        columns["start_time"].append(bucket_info["start_time"])
        columns["end_time"].append(bucket_info["end_time"])
    return pa.Table.from_pydict(columns)

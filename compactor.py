import glob
import time
import psutil
import duckdb
import os

BUCKET_DIR = "/data/pdmfc_fortigate/buckets"
MERGED_DIR = "/data/pdmfc_fortigate/merged"
PART_SIZE = 20  # Number of files per batch

def print_memory_usage():
    """Prints memory usage."""
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    print(f"Memory Usage: {mem_info.rss / (1024 * 1024):.2f} MB")

def compact_with_duckdb(files, output_file):
    """Merges parquet files using DuckDB with Snappy compression."""
    print(f" Merging {len(files)} files into {output_file} using DuckDB (Snappy)")
    conn = duckdb.connect()
    sql = f"COPY (SELECT * FROM read_parquet({files}, union_by_name=true)) TO '{output_file}' (FORMAT 'parquet', CODEC 'snappy');"
    
    start = time.time()
    try:
        conn.execute(sql)
        print(f" Done in {time.time() - start:.2f} sec")
        return True
    except Exception as e:
        print(f" DuckDB failed: {e}")
        return False
    finally:
        conn.close()

# Get all parquet files
files = sorted(glob.glob(os.path.join(BUCKET_DIR, "*.parquet")), key=os.path.getmtime)
if not files:
    print(" No parquet files found")
    exit()

# Create output folder
output_dir = os.path.join(MERGED_DIR, time.strftime("%Y-%m-%d"))
os.makedirs(output_dir, exist_ok=True)

# Merge in batches
for i in range(0, len(files), PART_SIZE):
    batch = files[i:i + PART_SIZE]
    output_file = os.path.join(output_dir, f"merged_{i//PART_SIZE}.parquet")
    
    print_memory_usage()
    
    if compact_with_duckdb(batch, output_file):
        for f in batch:
            os.remove(f)

print(" Compaction complete")

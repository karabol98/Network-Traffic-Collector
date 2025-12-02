import glob
import time
import duckdb
import psutil
import os


all_buckets = glob.glob('../../data/pdmfc_fortigate/old/*.parquet.old')

# sorted buckets
all_buckets = sorted(all_buckets)

PART_SIZE=20

# Partition the parquet files into groups of at most 100
partitioned_buckets = [all_buckets[i:i + PART_SIZE] for i in range(0, len(all_buckets), PART_SIZE)]

i = 0

# Function to print memory usage
def print_memory_usage(msg=""):
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    print(f"{msg};{mem_info.rss / (1024 * 1024):.2f};{mem_info.vms / (1024 * 1024):.2f}")

# Print initial memory usage
print_memory_usage("Start merging")
# Merge each partition separately
con = duckdb.connect()
try:
    for partitions in partitioned_buckets:
        sql = f"COPY (SELECT * FROM parquet_scan({partitions}, union_by_name = true)) TO '/tmp/merge_parquet_duckdb/merged_{i}.parquet'"
        con.query(sql)
        i += 1
        print_memory_usage(f"Finished merging partition {i}")
except Exception as e:
    print(e)
    print_memory_usage("Exception")
finally:
    con.close()
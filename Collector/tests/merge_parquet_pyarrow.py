import glob
import time
import pyarrow.parquet as pq
import pyarrow as pa
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
    print(f"{msg}; RSS: {mem_info.rss / (1024 * 1024):.2f} MB; VMS: {mem_info.vms / (1024 * 1024):.2f} MB")

# Print initial memory usage
print_memory_usage("Start merging")
# Merge each partition separately
for partitions in partitioned_buckets:
    tables = [pq.read_table(part) for part in partitions]
    pq.write_table(pa.concat_tables(tables, promote_options="default"), f'/tmp/merge_parquet_pyarrow/merged_{i}.parquet')
    i += 1
    print_memory_usage(f"Finished merging partition {i}")

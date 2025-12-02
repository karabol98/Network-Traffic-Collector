import pyarrow.parquet as pq
import os
import sys

def analyze_parquet_metadata(file_path):
    if not os.path.exists(file_path):
        print(f"Error: '{file_path}' doesn't exist")
        return

    try:
        parquet_file = pq.ParquetFile(file_path)
        metadata = parquet_file.metadata

        if metadata.num_row_groups > 10:
            print(f"{file_path}")
        # print(f"Number of Rows: {metadata.num_rows}")
        # print(f"Number of Columns: {metadata.num_columns}")
        # print(f"Created By: {metadata.created_by}")
        # print(f"Schema: {metadata.schema}")

        """
        for i in range(metadata.num_row_groups):
            row_group = metadata.row_group(i)
            print(f"\nRow Group {i}:")
            print(f"  Total Byte Size: {row_group.total_byte_size}")
            print(f"  Number of Rows: {row_group.num_rows}")
        """

    except Exception as e:
        print(f"Error reading Parquet file: {e}")

if __name__ == "__main__":
    analyze_parquet_metadata(sys.argv[1])

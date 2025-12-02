import pyarrow.parquet as pq

# Path to the Parquet file
parquet_file_path = "path/to/your/search-ms:displayname=Αποτελέσματα%20αναζήτησης%20σε%3A%20Κεντρική&crumb=System.Generic.String%3A(data%20index)&crumb=location:%3A%3A{F874310E-B6B7-47DC-BC84-B9E6B38F5903}"

# Try to read the file
try:
    table = pq.read_table(parquet_file_path)
    print(table)
except Exception as e:
    print(f"Error reading Parquet file: {e}")

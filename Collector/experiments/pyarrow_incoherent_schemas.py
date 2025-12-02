import pandas as pd
import pyarrow as pa
import time
import random
import tracemalloc
import pyarrow.parquet as pq
import os
import traceback

PANDAS_PARQUET_FILE="concatenated_data_pandas.parquet"
PYARROW_PARQUET_FILE="concatenated_data_pyarrow.parquet"

start_time = time.time()
# Data for the parquet files
NUM_ROWS1 = 10000000
data1 = {
    "_time": pd.date_range("2025-04-10", periods=NUM_ROWS1, freq="min"),
    "srcport": [f"{8080 + i % 100000}" for i in range(NUM_ROWS1)],
    "dstport": [f"{8082 + i % 100000}" for i in range(NUM_ROWS1)],
    "origin": [(8080 + i % 100000) for i in range(NUM_ROWS1)],
}

NUM_ROWS2 = 100000
data2 = {
    "_time": pd.date_range("2025-04-10", periods=NUM_ROWS2, freq="min"),
    "srcport": [str(random.randint(2000, 65000)).encode() for _ in range(NUM_ROWS2)],
    "newport": [f"{random.randint(2000, 65000)}" for _ in range(NUM_ROWS2)],
    "origin": [str(random.randint(2000, 65000)).encode() for _ in range(NUM_ROWS2)],  # Using bytes
}

end_time = time.time()
print(f"data creation execution time: {end_time - start_time:.6f} seconds")

# Time dataframe creation
start_time = time.time()
df1 = pd.DataFrame(data1)
df2 = pd.DataFrame(data2)
end_time = time.time()
print(f"DataFrame creation execution time: {end_time - start_time:.6f} seconds")

# Time conversion to Arrow Table
start_time = time.time()
table1 = pa.Table.from_pandas(df1)
table2 = pa.Table.from_pandas(df2)
end_time = time.time()
print(f"Arrow Table conversion execution time: {end_time - start_time:.6f} seconds")


print("Table Schemas:")
print(f"   Table 1: {table1.schema}")
print(f"   Table 2: {table2.schema}")

# concatenating the tables
# Explicitly set promotion type for the origin field to resolve incompatibility
## table = pa.concat_tables([table1, table2], promote_options={"origin": pa.string()})

# Use the function to create promotion options
tables_to_concat = [table1, table2]

# Attempt to concatenate tables with different schemas
start_time = time.time()
tracemalloc.start()
before_memory = tracemalloc.get_traced_memory()[0]
try:
    table = pa.concat_tables(tables_to_concat, promote_options="default")
except pa.lib.ArrowTypeError as e:
    # Handle the ArrowTypeError
    print(f"ArrowTypeError: {e}")
    print(f"Traceback: {traceback.format_exc()}")
except Exception as e:
    # Handle the exception
    print(f"Exception: {e}")
    print(f"Traceback: {traceback.format_exc()}")

after_memory = tracemalloc.get_traced_memory()[0]
memory_used = (after_memory - before_memory) / 1024 / 1024  # Convert to MB
tracemalloc.stop()
end_time = time.time()
print(f"Memory usage: {memory_used:.2f} MB")
print(f"Concatenation execution time: {end_time - start_time:.6f} seconds")


# Use pandas to handle schema compatibility
def make_schema_compatible_pandas(tables):
    """Convert tables to pandas, fix schema compatibility, then convert back to PyArrow"""
    pandas_dfs = [table.to_pandas() for table in tables]
    
    # Find all columns that exist in multiple tables
    all_columns = set()
    for df in pandas_dfs:
        all_columns.update(df.columns)
    
    # For each column, check if it has different types across tables
    for col in all_columns:
        col_types = {str(df[col].dtype) for df in pandas_dfs if col in df.columns}
        if len(col_types) > 1:
            # Convert to string in all DataFrames if types don't match
            for df in pandas_dfs:
                if col in df.columns:
                    df[col] = df[col].astype(str)
    
    # Concatenate and convert back to PyArrow
    concatenated_df = pd.concat(pandas_dfs, ignore_index=True)
    return pa.Table.from_pandas(concatenated_df)

# Apply the function to fix schema compatibility
start_time = time.time()
tracemalloc.start()
before_memory = tracemalloc.get_traced_memory()[0]
table = make_schema_compatible_pandas(tables_to_concat)
after_memory = tracemalloc.get_traced_memory()[0]
memory_used = (after_memory - before_memory) / 1024 / 1024  # Convert to MB
tracemalloc.stop()
end_time = time.time()
print(f"make_schema_compatible_pandas memory usage: {memory_used:.2f} MB")
print(f"make_schema_compatible_pandas execution time: {end_time - start_time:.6f} seconds")

# Write the concatenated table to a Parquet file
output_file = PANDAS_PARQUET_FILE
pq.write_table(table, output_file)
print(f"Concatenated data written to {output_file}")

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


# Apply the function to fix schema compatibility
start_time = time.time()
tracemalloc.start()
before_memory = tracemalloc.get_traced_memory()[0]
table = reconcile_schemas_and_concat_pyarrow_tables(tables_to_concat)
tracemalloc.stop()
end_time = time.time()
print(f"make_schema_compatible_with_pyarrow memory usage: {memory_used:.2f} MB")
print(f"make_schema_compatible_with_pyarrow execution time: {end_time - start_time:.6f} seconds")

output_file = PYARROW_PARQUET_FILE
pq.write_table(table, output_file)
print(f"Concatenated data written to {output_file}")

# Read the Parquet files back and compare them
start_time = time.time()
table1 = pq.read_table(PANDAS_PARQUET_FILE)
table2 = pq.read_table(PYARROW_PARQUET_FILE)
end_time = time.time()
print(f"Read Parquet files execution time: {end_time - start_time:.6f} seconds")
# Compare the two tables
if table1.equals(table2):
    print("The two tables are equal.")
else:
    print("The two tables are NOT equal.")
    # Custom comparison since PyArrow Table has no compare method
    print("Differences:")
    # Compare schemas
    if not table1.schema.equals(table2.schema):
        print("  - Schemas differ:")
        print(f"    Table 1: {table1.schema}")
        print(f"    Table 2: {table2.schema}")
    
    # Compare row count
    if table1.num_rows != table2.num_rows:
        print(f"  - Row count differs: table1={table1.num_rows}, table2={table2.num_rows}")
    
    # Compare column data (for columns that exist in both tables)
    common_columns = set(table1.column_names).intersection(set(table2.column_names))
    for col in common_columns:
        if not table1[col].equals(table2[col]):
            print(f"  - Data differs in column '{col}'")
# Clean up
os.remove(PANDAS_PARQUET_FILE)
os.remove(PYARROW_PARQUET_FILE)

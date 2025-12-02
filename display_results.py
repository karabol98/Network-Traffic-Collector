import os
import pyarrow.parquet as pq
import pandas as pd


base_directory = "./data"


if os.path.exists(base_directory):

    for index_folder in os.listdir(base_directory):
        bucket_folder = os.path.join(base_directory, index_folder, "buckets")
        if os.path.exists(bucket_folder):
            print(f"Αρχεία για το index '{index_folder}':")
            for filename in os.listdir(bucket_folder):
                file_path = os.path.join(bucket_folder, filename)
                if file_path.endswith(".parquet"):
                    print(f"Διαβάζοντας το αρχείο: {filename}")

                    df = pd.read_parquet(file_path)
                    print(df)
else:
    print("Δεν βρέθηκαν αποθηκευμένα buckets.")

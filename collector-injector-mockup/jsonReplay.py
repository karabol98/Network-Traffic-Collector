import os
import json
import random
import requests
from datetime import datetime, timedelta, timezone
import time
import sys
import glob
import msgspec

def expand_json_files(patterns):
    json_files = []
    for pattern in patterns:
        if os.path.isdir(pattern):
            json_files.extend(glob.glob(os.path.join(pattern, "*.json")))
        else:
            json_files.extend(glob.glob(pattern))
    return json_files

# Retrieve the patterns from command line arguments
if len(sys.argv) < 2:
    print("Usage: python jsonReplay.py <directory_or_file_or_pattern> [<directory_or_file_or_pattern> ...]")
    sys.exit(1)

patterns = sys.argv[1:]
json_files = expand_json_files(patterns)

if not json_files:
    print(f"No JSON files found matching the patterns: {patterns}")
    sys.exit(1)

# Function to convert custom time format to strftime-compatible format
def convert_time_format(custom_format):
    format_mappings = {
        "YYYY": "%Y",
        "MM": "%m",
        "DD": "%d",
        "HH": "%H",
        "mm": "%M",
        "ss": "%S"
    }
    for key, value in format_mappings.items():
        custom_format = custom_format.replace(key, value)
    return custom_format

# Function to update timestamps
def update_timestamps(data):
    now = datetime.now(timezone.utc)
    timefield = data.get("header", {}).get("timefield", "timestamp")
    timeformat = data.get("header", {}).get("timeformat", "%Y-%m-%d %H:%M:%S")  # Default format

    # Convert custom time format to strftime format
    timeformat = convert_time_format(timeformat)

    for event in data.get("events", []):
        # Generate a random timestamp within the last 5 seconds
        new_timestamp = now - timedelta(seconds=random.randint(0, 5))
        event[timefield] = new_timestamp.strftime(timeformat)

    return data

decoder = msgspec.json.Decoder(strict=False)
encoder = msgspec.json.Encoder()

msgpack_decoder = msgspec.msgpack.Decoder(strict=False)
msgpack_encoder = msgspec.msgpack.Encoder()

# Main loop
while True:
    if not json_files:
        print("No JSON files found.")
        break

    # Choose a random file
    selected_file = random.choice(json_files)
    print(f"Processing {selected_file}")

    # Load the JSON data
    with open(selected_file, 'r') as file:
        data = json.load(file)

    # Update timestamps
    updated_data = update_timestamps(data)

    enc_data = msgpack_encoder.encode(updated_data)

    # Send the JSON to the FastAPI app
    try:
        response = requests.post("http://localhost:8000/index", data=enc_data)
        print(f"Status Code: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send data: {e}")

    # Wait 5 seconds before the next iteration
    # time.sleep(5)

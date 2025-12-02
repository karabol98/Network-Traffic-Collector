import argparse
import requests
from datetime import datetime, timedelta
import random
import string
import uuid


def generate_events(max_events):
    # Possible random keys (excluding `_time` and `type`, which are always included)
    possible_keys = ["id", "name", "status", "value", "description", "priority", "tag"]

    # Helper to generate random strings
    def random_string(length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    # Helper to generate random data types
    def random_value():
        data_type = random.choice(["uuid", "string", "int", "float", "bool", "none"])
        if data_type == "uuid":
            return str(uuid.uuid4())
        elif data_type == "string":
            return random_string()
        elif data_type == "int":
            return random.randint(1, 1000)
        elif data_type == "float":
            return round(random.uniform(1.0, 1000.0), 2)
        elif data_type == "bool":
            return random.choice([True, False])
        elif data_type == "none":
            return None

    events = []
    for _ in range(max_events):
        # Generate a random timestamp within the last hour
        event_time = (datetime.now() - timedelta(seconds=random.randint(0, 60))).isoformat()

        # Generate a random number of additional fields (0 to 4 random keys)
        num_extra_fields = random.randint(0, 4)
        extra_fields = {
            random.choice(possible_keys): random_value() for _ in range(num_extra_fields)
        }

        # Ensure `_time` and `type` are always present
        event = {
            "_time": event_time,
            "type": random.choice(["event", "log", "alert", "notification"]),
        }

        # Merge extra fields
        event.update(extra_fields)

        events.append(event)

    return events


def send_data(url, num_packets, max_records, max_events, max_indexes):
    try:
        print(f"Sending data to the server {url}...")
        for i in range(num_packets):
            data = []
            for _ in range(max_records):
                data.append({"index": f"index_{random.randint(1, max_indexes)}",
                             "events": generate_events(max_events)})
            response = requests.post(url, json=data)
            response.raise_for_status()
            print(f"Packet {i + 1}/{num_packets} sent successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error sending data: {e}")


def parse_args():
    parser = argparse.ArgumentParser(description="Data sending simulator.")
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:8000/collect", help="The server's URL.")
    parser.add_argument("--num-packets", type=int, default=10, help="Number of packets to be sent.")
    parser.add_argument("--max-records", type=int, default=100, help="Maximum number of records per packet.")
    parser.add_argument("--max-events", type=int, default=50, help="Maximum number of events per packet.")
    parser.add_argument("--max-indexes", type=int, default=3, help="Maximum number of indexes used.")
    return parser.parse_args()


def main():
    args = parse_args()
    send_data(args.url, args.num_packets, args.max_records, args.max_events, args.max_indexes)


if __name__ == "__main__":
    main()

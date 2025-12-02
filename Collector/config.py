
from datetime import timedelta, timezone, datetime
from humanfriendly import parse_size
import humanfriendly
import toml
import socket
from zoneinfo import ZoneInfo

config = {
    "collector": {
        "max_buckets": 5,
        "max_bucket_size": "1GB",
        "bucket_time_duration": "1h",  # Or any valid time string format
        "port": 8000,
        "bucket_store": "./data",
        "log_level": "INFO",
        "bucket_start_time_delta": "10min",
        "bucket_idle_time": "10min",  # If no events received for this time, the bucket is saved and removed
        "cleanup_interval": "60s",  # How often the cleanup process runs (default 60 seconds)
        "compaction_interval": "5min",  # How often the compaction process runs (default 60 seconds)
        "metrics_interval": "1min",  # How often the processmetrics are updated
        "bucket_duration_threshold": "15min",  # Buckets older than this will be saved and removed
        "compaction_threshold": "100MB",  # Files larger than this will not be compacted
        "compaction_file_limit": 200,  # Limit the number of files to compact at once
        "max_bucket_events": 100000, # limit the number of events in a bucket to avoid memory issues and slow pyarrow concat
        "host": socket.gethostname(),
        "timezone": "UTC",

    },

    "compaction": {
        "disabled": False,
    },
    "metrics": {
        "disabled": False,
    },
    "cleanup": {
        "disabled": False,
    }
}

try:
    newconfig = toml.load("config.toml")
    config["collector"].update(newconfig["collector"])
    config["compaction"].update(newconfig["compaction"])
    config["metrics"].update(newconfig["metrics"])
    config["cleanup"].update(newconfig["cleanup"])
except FileNotFoundError:
    print("Configuration file 'config.toml' not found. Using default configuration.")

def get_config():
    global config
    return config

def value(key, default=None):
    paths = key.split(".")
    value = get_config()
    for path in paths:
        if not isinstance(value, dict):
            return default
        value = value.get(path, None)
        if value is None:
            return default

    return value

def get_collector_config():
    return get_config().get("collector")

def get_compactor_config():
    return get_collector_config().get("compaction")

def compaction_value(key, default=None):
    return get_compactor_config().get(key, default)

def config_value(key, default=None):
    return get_collector_config().get(key, default)

def config_size(key, default=None):
    return parse_size(config_value(key, default))

def config_timedelta(key, default=None):
    return timedelta(seconds=config_timespan(key, default))

def config_timespan(key, default=None):
    return humanfriendly.parse_timespan(config_value(key, default))

def config_zoneinfo() -> ZoneInfo:
    try:
        return ZoneInfo(config_value("timezone"))
    except Exception as e:
        print(f"Error loading timezone: {e}")
        return ZoneInfo("UTC")

def config_timezone() -> timezone:
    return datetime(2024,1,1,0,0).astimezone(config_zoneinfo()).tzinfo

TZ = config_timezone()

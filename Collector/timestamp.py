import logging
import time
from datetime import datetime, timezone
import ciso8601
from config import TZ

format_mappings = {
    'YYYY': '%Y',
    'MM': '%m',
    'DD': '%d',
    'hh': '%H',
    'mm': '%M',
    'ss': '%S'
}

custom_mappings = ["iso8601", "epoch", "unix", "unix_ms", "rfc3339","datetime"]
logger = logging.getLogger("uvicorn.error")

def python_format(dateformat:str):
    if not dateformat or dateformat in custom_mappings:
        return dateformat
     # Convert format if it contains non-standard tokens
    python_format = dateformat
    for token, replacement in format_mappings.items():
        if token in python_format:
            python_format = python_format.replace(token, replacement)

    return python_format

def smart_strptime(value, timeformat = None, tz=TZ):
    if timeformat == "datetime" or isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=tz)
        return value

    if isinstance(value, time.struct_time):
        return datetime.fromtimestamp(time.mktime(value), tz)

    if timeformat == "unix" or timeformat == "epoch" or isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz)

    if timeformat == "unix_ms" or timeformat == "unixms":
        return datetime.fromtimestamp(float(value) / 1000, tz)

    if timeformat == "iso8601" or timeformat == "rfc3339" or not timeformat:
        try:
            result = ciso8601.parse_datetime(value)
            if result.tzinfo is None:
                result = result.replace(tzinfo=tz)
            return result
        except Exception as e:
            logger.error(f"Error parsing time value '{value}' with format '{timeformat}': {e}")
            return None
    try:
        result = datetime.strptime(value, timeformat)
        if result.tzinfo is None:
            result = result.replace(tzinfo=tz)    
        return result
    except Exception as e:
        logger.error(f"Error parsing time value '{value}' with format '{timeformat}': {e}")
        return None


def parse_event_times(id, source_col, timeformat):
    if len(source_col) == 0:
        return source_col

    if timeformat == "datetime" and isinstance(source_col[0], datetime):
        return source_col

    ev_time = datetime.now(TZ) # store the ingestion time for the first event with no time value
    start_time_parse = time.time()
    time_col = [None] * len(source_col)
    format_str = python_format(timeformat)

    # Process each value with direct enumerate for maximum efficiency
    for i, value in enumerate(source_col):
        if value is not None:
            parsed_time = smart_strptime(value, format_str)
            if parsed_time:
                ev_time = parsed_time
        time_col[i] = ev_time

    parse_time_elapsed = time.time() - start_time_parse
    logger.debug(f"{id}: Time to parse time values: {parse_time_elapsed:.6f} seconds")
    return time_col

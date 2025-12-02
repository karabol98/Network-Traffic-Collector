import logging
import asyncio
from datetime import datetime
from config import TZ
import pyarrow as pa
from bucket_manager import BucketManager
from storage import filter_data_with_duckdb, get_redis_pool
from msgspec import msgpack, json
from constants import ACTIVE_STREAM_ALL_INDEXES
import gzip

logger = logging.getLogger('uvicorn.error')

encoder = json.Encoder()
msgpack_decoder = msgpack.Decoder(strict=False)

def get_active_interested_streams(active_streams_per_index, index):
    # Retrieve the list for the given index, defaulting to an empty list
    index_streams = active_streams_per_index.get(index, [])
    # Retrieve the list for the special key
    all_streams = active_streams_per_index.get(ACTIVE_STREAM_ALL_INDEXES, [])
    # Use a set to ensure unique values
    unique_streams = list(set(index_streams + all_streams))

    return unique_streams

async def notify_array(active_streams, active_streams_per_index,columns : list[str], array : list[list[any]], index):
    if len(active_streams) == 0:
        logger.debug("No active streams.")
        return

    start_time = datetime.now(TZ)

    # Convert array and columns to Arrow table
    table = pa.Table.from_arrays(array, names=columns)

    # Notify custom streams (only new batch)
    for stream_id in get_active_interested_streams(active_streams_per_index, index):
        stream_info = active_streams.get(stream_id, {})
        # Check if the stream has listeners
        if stream_info.get('listeners') > 0:
            filtered_data = filter_data_with_duckdb([table], stream_info['filters'])
            # Check if there are any rows left after filtering
            if filtered_data.num_rows > 0:
                await publish_events(stream_info, filtered_data)
    logger.debug(f"Notified events in {datetime.now() - start_time}.")

async def notify_events(active_streams, active_streams_per_index, events, index):
    if len(active_streams) == 0:
        logger.debug("No active streams.")
        return

    start_time = datetime.now(TZ)

    # Convert to Arrow table
    table = pa.Table.from_pylist(events)

    # Notify custom streams (only new batch)
    for stream_id in get_active_interested_streams(active_streams_per_index, index):
        stream_info = active_streams.get(stream_id, {})
        if stream_info.get('listeners') > 0:
            filtered_data = filter_data_with_duckdb([table], stream_info['filters'])
            if filtered_data.num_rows > 0:
                await publish_events(stream_info, filtered_data)
    logger.debug(f"Notified events in {datetime.now(TZ) - start_time}.")


async def consume_from_redis(active_streams, active_streams_per_index, manager):
    logger.info("✅ Starting Redis consumer...")
    redis_channel = "input"
    while manager.running:
        try:
            message = get_redis_pool().brpop([redis_channel], timeout=1)
            if message:
                logger.debug(f"Received message from Redis: {message[1][:500]}...")
                text = message[1]

                if text:
                    # Check if the message is gzipped by looking for the gzip magic number
                    if len(text) > 2 and text[:2] == b'\x1f\x8b':
                        try:
                            text = gzip.decompress(text)
                            logger.debug("Decompressed gzipped data")
                        except Exception as e:
                            logger.error(f"Failed to decompress gzipped data: {e}")

                    data = ""
                    try:
                        # Optionally: try to decode as msgpack using msgpack library
                        data = msgpack_decoder.decode(text)
                        size = len(text)
                        await background_task(active_streams, active_streams_per_index, manager, data, size)
                    except Exception as e:
                        logger.exception(f"can't process {text[:500]}: {e}")
            await asyncio.sleep(0.000001)
        except Exception as e:
            logger.exception(f"Error consuming from Redis: {e}")
            await asyncio.sleep(10)
    logger.info("Shutting down Redis consumer.")

async def background_task(active_streams, active_streams_per_index, manager : BucketManager, data, size : int):
    start_time = datetime.now(TZ)

    if "header" not in data:
        logger.error("Missing header in request.")
        logger.debug(f"Failed to index data in {datetime.now(TZ) - start_time}.")
        return "Missing header in request.", 400

    header = data.get("header", {})

    if "events" not in data:
        logger.error("Missing events in request.")
        logger.debug(f"Failed to index data in {datetime.now(TZ) - start_time}.")
        return "Missing events field in request.", 400

    events = data.get("events", [])
    index = header.get("index", "main")
    format = header.get("format", "metago").lower()
    if format == "msgpack2" or format == "metapack":
        columns = data.get("columns", [])
        asyncio.create_task(manager.process_array(index,header,columns, events, size))
        asyncio.create_task(notify_array(active_streams, active_streams_per_index,columns, events, index))
        return

    timefield = header.get("timefield", "_time")
    for event in events:
        if timefield not in event:
            logger.warning(f"Skipping event without time field: {event}")
            continue

        timestamp = event[timefield]
        event["_time"] = timestamp
        event.update(header)

    await manager.process_events(index, events, size)

    asyncio.create_task(notify_events(active_streams, active_streams_per_index, events, index))


async def publish_events(stream_info, data: pa.Table):
    if data and stream_info and 'channel' in stream_info and data.num_rows > 0 and stream_info.get('listeners') > 0:
        try:
            # Send each record individually to the specified Redis channel
            for record in data.to_pylist():
                record_json = encoder.encode(record)
                logger.debug(f"Broadcasting to {stream_info['channel']}: {record_json}")
                get_redis_pool().publish(stream_info['channel'], record_json)

        except Exception as e:
            logger.error(f"Failed to send data for broadcasting: {e}")

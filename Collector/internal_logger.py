
from datetime import datetime
import logging
import socket
import asyncio
from bucket_manager import BucketManager
from config import TZ, config_value

host = socket.gethostname()
INTERNAL_INDEX = "_internal"

class InternalLogHandler(logging.Handler):
    def __init__(self, bucket_manager : BucketManager, logger, source):
        LOG_LEVEL : str = config_value("log_level")
        super().__init__(LOG_LEVEL)
        self.logger = logger
        self.source = source
        self.bucket_manager : BucketManager = bucket_manager
        self.formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        logger.addHandler(self)

    def emit(self, record):
        try:
            # Format the log message
            msg = self.format(record)

            # Prepare log entry
            # Format timestamp for consistency
            timestamp = datetime.fromtimestamp(record.created, tz=TZ)

            # Create log entry as an array instead of dictionary
            log_entry = {
                "_time": timestamp,  # _time
                "_raw": msg,        # _raw
                "_host": host, # _host
                "_sourcetype": 'internal',      # _sourcetype
                "_source": self.source,  # _source
                "_index": INTERNAL_INDEX,
                "severity": record.levelname
            }

            try:
                # Check if we're in an event loop
                asyncio.get_running_loop()
                # If we have an active event loop, schedule the task
                asyncio.create_task(self.bucket_manager.process_events(INTERNAL_INDEX, [log_entry], len(str(log_entry))))
            except RuntimeError:
                # No running event loop, create a new one and run the task
                self.bucket_manager.process_events(INTERNAL_INDEX, [log_entry], len(str(log_entry)))

        except Exception:
            print("handle record error")
            self.handleError(record)

    def flush(self):
        # Check if we're in an event loop
        try:
            asyncio.get_running_loop()
            # If we have an active event loop, schedule the flush as a task
            asyncio.create_task(self.bucket_manager.flush_index(INTERNAL_INDEX))
        except RuntimeError:
            # No running event loop, create a new one and run the flush
            asyncio.run(self.bucket_manager.flush_index(INTERNAL_INDEX))

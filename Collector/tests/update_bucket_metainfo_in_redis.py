import os
from storage import store_parquet_buckets_info, get_redis_pool
import asyncio
import logging
import sys
logger = logging.getLogger("uvicorn.error")
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.DEBUG)

async def main():
	await store_parquet_buckets_info(os.path.join(os.path.dirname(__file__),"..","..","data"))

if __name__ == "__main__":
	asyncio.run(main())
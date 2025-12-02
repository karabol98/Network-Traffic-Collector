import os
import json
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import duckdb
import logging
import settings  # Import settings from your collector

# Load settings from config.toml
try:
    import toml
    config = toml.load("config.toml")
except FileNotFoundError:
    raise RuntimeError("Configuration file 'config.toml' not found. Exiting.")

webapp_config = config.get("webapp", {})
BUCKET_STORE = webapp_config.get("bucket_store", "data")  # Same bucket store as the collector
LOG_LEVEL = webapp_config.get("log_level", "INFO")
PORT = webapp_config.get("port", 8080)

# Ensure the bucket storage directory exists
if not os.path.exists(BUCKET_STORE):
    raise RuntimeError(f"Bucket store directory '{BUCKET_STORE}' does not exist. Check your collector configuration.")

# Configure logging
logger = logging.getLogger('uvicorn.error')

logger.info(f"Starting collector service on port {PORT}...")

# Initialize FastAPI app
app = FastAPI()

class QueryRequest(BaseModel):
    query: str

@app.get("/")
async def home():
    logger.info("Home endpoint accessed.")
    return {"message": "Welcome to the iTrust6G Web App. Use /query to interact with data."}

@app.post("/query")
async def run_query(request: QueryRequest):
    """
    Run a SQL query on the Parquet files stored by the collector.
    """
    query = request.query
    try:
        logger.debug(f"Executing query: {query}")
        parquet_path = os.path.join(BUCKET_STORE, "**/*.parquet")  # Use all Parquet files
        result = duckdb.query(f"SELECT * FROM '{parquet_path}' WHERE {query}").to_df()
        return JSONResponse(content=json.loads(result.to_json(orient="records")), status_code=200)
    except Exception as e:
        logger.error(f"Query failed: {e}")
        raise HTTPException(status_code=400, detail=f"Query failed: {e}")

@app.get("/files")
async def list_parquet_files():
    """
    List all the Parquet files saved by the collector.
    """
    files = []
    for root, _, filenames in os.walk(BUCKET_STORE):
        for filename in filenames:
            if filename.endswith(".parquet"):
                files.append(os.path.join(root, filename))
    logger.debug("Listed Parquet files.")
    return {"files": files}

@app.get("/data/{file_name}")
async def read_parquet_file(file_name: str):
    """
    Read data from a specific Parquet file.
    """
    file_path = os.path.join(BUCKET_STORE, file_name)
    if not os.path.exists(file_path):
        logger.warning(f"File not found: {file_name}")
        raise HTTPException(status_code=404, detail="File not found")

    try:
        result = duckdb.query(f"SELECT * FROM '{file_path}'").to_df()
        logger.debug(f"Read data from file: {file_name}")
        return JSONResponse(content=json.loads(result.to_json(orient="records")), status_code=200)
    except Exception as e:
        logger.error(f"Error reading file {file_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Error reading file: {e}")

def main():
    """
    Main function to start the web app.
    """
    import uvicorn


    uvicorn.run(
        "webapp:app",
        host="0.0.0.0",
        port=PORT,
        log_level=LOG_LEVEL.lower(),
        log_config=settings.LOGGING_CONFIG,  # Use logging configuration from settings.py
    )

if __name__ == "__main__":
    main()

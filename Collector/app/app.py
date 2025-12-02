import os
import traceback
import duckdb
import toml
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi import Request
import glob
import logging
import settings
import re

app = FastAPI()

# Mount the 'static' folder to serve static files like images, CSS, etc.
app.mount("/static", StaticFiles(directory="static"), name="static")

# Load the configuration from a TOML file
config = toml.load("config.toml")
app_config = config.get("app", {})
PARQUET_PATH = app_config.get("parquet_path", "/app/data")
PORT = app_config.get("port", 8000)  # Get the port from the config file, default to 8000
LOG_LEVEL = app_config.get("log_level", "INFO")  # Get the log level from the config file, default to INFO

logger = logging.getLogger('uvicorn.error')
logger.info(f"Starting collector service on port {PORT}...")

# Initialize Jinja2 template renderer
templates = Jinja2Templates(directory="templates")
from_re = re.compile(r"FROM\s+(\w+)", re.IGNORECASE)

# Function to get available indices (folders) in the parquet path
def get_indices():
    indices = []
    # List all items in the first level of /app/data/
    for item in os.listdir(PARQUET_PATH):
        # Check if the item is a directory and not the 'buckets' directory
        item_path = os.path.join(PARQUET_PATH, item)
        if os.path.isdir(item_path) and item != "buckets":
            indices.append(item)  # Add the index directory (not buckets)
    return sorted(indices)

# Serve the HTML page for the web app
@app.get("/")
async def root(request: Request):
    indices = get_indices()  # Get available indices
    return templates.TemplateResponse("index.html", {"request": request, "indices": indices})

@app.get("/query")
async def query_parquet_files(index: str, files: str, query: str):
    """
    Query parquet files with DuckDB SQL syntax.
    :param index: Index (directory) selected by the user
    :param files: Wildcard or file pattern entered by the user
    :param query: SQL query to run on Parquet files
    :return: Query result in JSON format
    """
    # Connect to DuckDB in-memory
    con = duckdb.connect()

    # Determine the path for the index folder selected by the user
    index_path = os.path.join(PARQUET_PATH, index)

    # Ensure that the files pattern ends with ".parquet"
    if not files.endswith(".parquet"):
        files = files + ".parquet"  # Append ".parquet" if missing

    # Construct the file path(s) based on user input
    logger.debug(f"Filtering for: {files}")

    # List all files in the index directory that match the pattern
    path_pattern = os.path.join(index_path, "buckets", files)  # Assuming 'buckets' is the subfolder
    logger.debug(f"Using path pattern: {path_pattern}")

    # Use glob to expand the wildcard path and find matching files
    matched_files = glob.glob(path_pattern)

    # Check if no files matched the pattern
    if not matched_files:
        logger.error(f"No files found for pattern: {path_pattern}")
        return JSONResponse(content={"error": f"No files found matching the pattern: {path_pattern}"})

    # Modify the query to use the Parquet files directly in the FROM clause
    query_with_files = from_re.sub(f"FROM read_parquet('{path_pattern}', union_by_name = true)", query)  # Replace "FROM table" with the actual files

    logger.debug(f"Executing query: {query_with_files}")

    # Execute the query on the Parquet files
    result = ""
    try:
        result = con.execute(query_with_files).fetchall()
    except Exception as e:
        logger.exception(f"Error executing query: {e}")
        return JSONResponse(content={"error": f"Error executing query: {str(e)} " + traceback.format_exc()})

    # Format the result as a list of dictionaries
    column_names = [desc[0] for desc in con.description]  # Extract column names from the cursor description
    formatted_result = [dict(zip(column_names, row)) for row in result]

    # Return the query result as JSON
    return JSONResponse(content={"result": formatted_result})

# If the script is executed directly, start the FastAPI server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        log_level=LOG_LEVEL.lower(),
        log_config=settings.LOGGING_CONFIG
    )

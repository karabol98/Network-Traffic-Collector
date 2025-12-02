import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime
from fastapi.exceptions import RequestValidationError
from config import compaction_value, config_value, TZ, value
from fastapi.encoders import jsonable_encoder
from history import add_user_query, get_history, search_history
import pyarrow.parquet as pq
from bucket_manager import cpu_metrics_task, get_bucket_manager, get_meta_indexes, run_compaction_task, bucket_cleanup_task
import duckdb
import pyarrow as pa
from internal_logger import InternalLogHandler
from storage import count_records_in_parquet_files_from_redis, count_records_in_parquet_files_from_files, filter_data_with_duckdb, get_redis_pool, get_redis_info, store_parquet_buckets_info
from task_manager import TaskManager
from fastapi import Depends, FastAPI, Request, Query, HTTPException, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.gzip import GZipMiddleware
import uuid
from typing import Dict, List, Any, Optional
from contextlib import asynccontextmanager
import settings
from timestamp import smart_strptime
import utils
from worker import consume_from_redis
from constants import ACTIVE_STREAM_ALL_INDEXES, CLOSE_STREAM_MESSAGE
from query import MetaQuery
import uvicorn
import psutil
from routes.auth import logout, login, router as auth_router
from routes.users import router as users_router
from routes.roles import router as roles_router
from models import User
from schemas import UserLogin
from database import get_db
from sqlalchemy.orm import Session
from routes import sigma, users, auth, roles
from database import engine
from utils import create_base_data, get_db
import sys
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from bucket_manager import bucket_manager
from sigma_scheduler.app.rule_scheduler import run_scheduler
from query import MetaQuery as MetaCommandParser
from models import Base as UserBase




# Attempt to avoid thread deadlock in duckdb
duckdb.execute("SET threads TO 1")

# Attempt try disabling memory mapping for Arrow
pa.set_memory_pool(pa.default_memory_pool())

BUCKET_STORE : str = config_value("bucket_store", "data")
PORT : int = config_value("port", 8000)
LOG_LEVEL : str = config_value("log_level", "INFO")

# try to read file version.txt to get the version of the collector, if not found set to 'unknown'
try:
    with open("version.txt", "r") as f:
        VERSION : str = f.read().strip()
except FileNotFoundError:
    VERSION = "unknown"

RELEASE_LOCK_INFO_MSG = "Processing query release Lock"
NO_VALID_INDEXES_MSG = "No valid indices found in query, try extending the time range or checking available indexs (select * from _indexes)."


# Configure logging
logger = logging.getLogger('uvicorn.error')
logger.info(f"Starting collector service on port {PORT}...")
logger.info(get_redis_info())

# Initialize Jinja2 template renderer
templates = Jinja2Templates(directory="templates")

# Ensure the bucket storage directory exists
os.makedirs(BUCKET_STORE, exist_ok=True)
if not os.access(BUCKET_STORE, os.W_OK):
    logger.error(f"No write permissions for BUCKET_STORE: {BUCKET_STORE}")
    exit(1)

# Initialize the bucket manager and task manager
manager = get_bucket_manager()
task_manager = TaskManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await startup_tasks()

    yield  # The app runs during this period
    try:
        await asyncio.wait_for(shutdown_tasks(), timeout=10.0)
        print("Graceful shutdown completed")
    except asyncio.TimeoutError:
        print("Shutdown timed out!")
    except asyncio.exceptions.CancelledError:
        print("Cancelled Error Caught")
    except KeyboardInterrupt:
        print("Keyboard Interrupt Caught")
    except Exception as e:
        print(f"Error during shutdown: {e}")

    print_threads()

async def startup_tasks():
    InternalLogHandler(manager, logger, "collector")
    InternalLogHandler(manager, logging.getLogger("uvicorn.access"), "web")
    UserBase.metadata.create_all(bind=engine)
    # Create base data if needed
    utils.create_base_data(next(get_db()))
    # Startup Logic
    start_task_time = time.time()
    start_time = start_task_time
    await store_parquet_buckets_info(manager.BUCKET_STORE)
    logger.info(f"✅ Buckets updated to redis in {time.time() - start_task_time:.2f} seconds.")
    start_task_time = time.time()
    load_active_streams()
    logger.info(f"✅ Active streams loaded on startup in {time.time() - start_task_time:.2f} seconds.")
    start_task_time = time.time()
    task_manager.start_workers()
    task_manager.add_task(consume_from_redis(active_streams, active_streams_per_index, manager))


    asyncio.create_task(run_scheduler(bucket_manager))


    if not value("cleanup.disabled"):
        task_manager.add_task(bucket_cleanup_task(manager))
    else:
        logger.info("Cleanup task disabled.")

    if not value("compaction.disabled"):
        task_manager.add_task(run_compaction_task(manager))
    else:
        logger.info("Compaction task disabled.")

    if not value("metrics.disabled"):
        task_manager.add_task(cpu_metrics_task(manager))
    else:
        logger.info("Metrics task disabled.")

    logger.info(f"✅ Task manager started on startup in {time.time() - start_task_time:.2f} seconds.")
    logger.info(f"✅ Startup completed in {time.time() - start_time:.2f} seconds.")


app = FastAPI(lifespan=lifespan)
app.add_middleware(GZipMiddleware, compresslevel=9, minimum_size=1000)
app.include_router(sigma.router, prefix="/sigma", tags=["Sigma Rules Management"])
app.include_router(users.router, prefix="/users", tags=["Users Management"])
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(roles.router, prefix="/roles", tags=["Roles Management"])
# app.include_router(sigma_import_router, prefix="/sigma", tags=["Sigma Rules"])

# Mount the 'static' folder to serve static files like images, CSS, etc.
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    # Skip logging for non-authenticated routes or static files if needed
    path = request.url.path
    if path.startswith("/static") or path == "/login" or path == "/admin/login" or path == "/docs":
        response = await call_next(request)
        return response
    
    start_time = time.time()
    
    # Try to get current user from token (if available)
    user = None
    try:
        token = request.cookies.get("access_token") or request.headers.get("Authorization", "").replace("Bearer ", "")
        if token:
            user = utils.get_user_from_token(next(get_db()), token)
    except Exception as e:
        pass
    
    # Process the request
    req_id = uuid.uuid4()
    try:
        logger.debug(f"[{req_id}] Starting request: {request.method} {path}")
        response = await call_next(request)
        
        # Log successful request if authenticated
        execution_time = time.time() - start_time
        if user:
            await utils.create_audit_log(
                user=user,
                action=request.method.lower(),
                resource_type="api",
                resource_id=path,
                success=response.status_code < 400,
                details={
                    "status_code": response.status_code,
                    "processing_time": execution_time,
                },
                request=request
            )

        logger.debug(f"[{req_id}] Ending request OK: {request.method} {path} ({execution_time}s)")
        return response
    
    except Exception as e:
        # Log exception
        execution_time = time.time() - start_time
        if user:
            await utils.create_audit_log(
                user=user,
                action=request.method.lower(),
                resource_type="api",
                resource_id=path,
                success=False,
                details={
                    "processing_time": execution_time,
                },
                error_message=str(e),
                request=request
            )
        logger.debug(f"[{req_id}] Ending request FAIL: {request.method} {path} ({execution_time}s)")
        raise


async def remove_null_cols(result_list):
    """
    Remove columns that have null values in all rows from the result list.
    
    :param result_list: List of dictionaries containing query results
    :return: List of dictionaries with null columns removed
    """
    if not result_list or len(result_list) == 0:
        return result_list, {}
    
    # Find columns that are null in all rows
    null_columns = set(result_list[0].keys())
    for row in result_list:
        non_null_cols = {k for k, v in row.items() if v is not None}
        null_columns -= non_null_cols
        if not null_columns:
            # If we found at least one non-null value for each column, stop checking
            break
    
    # Remove null columns from all rows
    if null_columns:
        result_list = [{k: v for k, v in row.items() if k not in null_columns} for row in result_list]
    
    return result_list, null_columns

async def shutdown_tasks():
    # Shutdown Logic
    task_manager.shutdown()
    await manager.shutdown()
    logger.info("✅ Active streams and buckets saved on shutdown.")

def print_threads():
    # List all child processes
    try:
        current_process = psutil.Process()
        children = current_process.children(recursive=True)

        logger.info(f"Child processes ({len(children)}):")
        for child in children:
            try:
                cmd = ' '.join(child.cmdline()) if child.cmdline() else "Unknown command"
                status = child.status()
                memory = child.memory_info().rss / (1024 * 1024)  # Convert to MB
                logger.info(f"PID: {child.pid}, Status: {status}, Memory: {memory:.2f}MB, Command: {cmd}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                logger.info(f"PID: {child.pid}, Status: Process no longer exists or access denied")
    except ImportError:
        logger.info("psutil module not available for process listing")
    except Exception as e:
        logger.exception(f"Error listing child processes: {e}")


# Active streams (uuid: {indexes: [], filters: {}})
active_streams: Dict[str, Dict[str, Any]] = {}

# Active streams per index (index: [uuid])
active_streams_per_index: Dict[str, List[str]] = {}


def filter_user_index_read_permissions(db_user: User, available_indexes: List[str]) -> List[str]:
    """
    Filter the available indexes by the user's read permissions.
    :param db_user: The user object to check read permissions against.
    :param available_indexes: The list of available index names.
    :return: The list of available index names the user can read.
    """
    user_available_indexes = []
    if db_user and not utils.has_admin_role(db_user):
        logger.debug(f"Filtering indexes for user {db_user.username}: {available_indexes}")
        for index in available_indexes:
            if utils.user_has_read_access_on_index(db_user, index):
                logger.debug(f"User {db_user.username} has read access to index: {index}")
                user_available_indexes.append(index)
    else:
        # If the user is admin or None, return all available indexes
        user_available_indexes = available_indexes

    logger.debug(f"All available indexes for user {db_user.username if db_user else None}: {user_available_indexes}")
    return sorted(set(user_available_indexes))


# function to retrieve all indexes from files and in memory accessible to the user
def get_all_indices(db_user: User = None, start_timestamp: datetime = None, end_timestamp: datetime = None) -> List[str]:
    """
    Get all available indexes for the user.
    :param db_user: The user object to check read permissions against.
    :param start_timestamp: Start timestamp for filtering indexes.
    :param end_timestamp: End timestamp for filtering indexes.
    :return: List of available index names the user can read.
    """
    indices = utils.get_all_indexes_raw(start_timestamp, end_timestamp)
    # If the user is not admin, filter the indexes by the user's permissions
    indices = filter_user_index_read_permissions(db_user, indices)

    return sorted(set(indices))

@app.post("/history")
@app.post("/history/")
async def add_query_ws(entry: str, current_user: User = Depends(utils.get_current_user_oauth)):
    add_user_query(entry, current_user.id)


@app.get("/history")
@app.get("/history/")
async def get_history_ws(current_user: User = Depends(utils.get_current_user_oauth)):
    return get_history(current_user.id)


@app.get("/history/search")
@app.get("/history/search/")
async def search_history_ws(q: str, current_user: User = Depends(utils.get_current_user_oauth)):
    return search_history(q, current_user.id)


# Serve the HTML page for the web app
@app.get("/", response_class=HTMLResponse)
async def root(request: Request, token: str = Depends(utils.get_auth_token)):
    logger.debug(f"Veryfying token: {token}")
    if utils.verify_token(token) is None:
        logger.error("token is None")
        return RedirectResponse(url="/login")

    return templates.TemplateResponse("index.html", {"request": request, "version": VERSION})


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "version": VERSION})

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # BREAKPOINT HERE
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=jsonable_encoder({"detail": exc.errors()}),
    )

@app.post("/login")
async def login_endpoint(request: Request, db: Session = Depends(get_db)):
    """
    Endpoint for user authentication.
    Uses OAuth2 password flow to authenticate users and return access token.
    """
    try:
        # First try to parse as form data
        user_login = None
        content_type = request.headers.get("Content-Type", "")

        if "application/json" in content_type:
            # Handle JSON request
            json_data = await request.json()
            if json_data and "username" in json_data and "password" in json_data:
                user_login = UserLogin(username=json_data["username"], password=json_data["password"])
            else:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON format, missing username or password")
        elif "application/x-www-form-urlencoded" in content_type:
            # Handle form data
            form_data_dict = await request.form()
            if "username" in form_data_dict and "password" in form_data_dict:
                user_login = UserLogin(username=form_data_dict["username"], password=form_data_dict["password"])
            else:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid form data, missing username or password")

        # Create response object
        return await login(request, user_login, db)


    except HTTPException as e:
        logger.error(f"Login failed: {e.detail}")
        raise e
    except Exception as e:
        logger.exception(f"Unexpected error during login: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during login"
        )


@app.post("/logout")
async def logout_redirect(request: Request, current_user: User = Depends(utils.get_current_user_oauth), db: Session = Depends(get_db)):
    """
    Redirects internally to the logout ws.
    """
    return await logout(request, current_user, db)


@app.get("/user_info", response_class=HTMLResponse)
async def user_info(request: Request, db: Session = Depends(get_db), token = Depends(utils.get_auth_token)):
    logger.debug(f"Veryfying token: {token}")
    if utils.verify_token(token) is None:
        logger.error("token is None")
        return RedirectResponse(url="/login")

    db_user = utils.get_user_from_token(db, token)
    if db_user is None:
        logger.error("User not found")
        return RedirectResponse(url="/login")

    # Render user info page
    return templates.TemplateResponse("user_info.html", {
        "request": request,
        "username": db_user.username,
        "email": db_user.email,
        "roles": ",".join([role.name for role in db_user.roles]),  # Assuming you have a roles attribute in the User model
        "indexes": db_user.permissions,  # Assuming you have an permissions attribute in the User model
        "version": VERSION  # Or fetch dynamically
    })


# Serve static files from /web directly as templates
@app.get("/web/{path:path}")
async def serve_web_content(request: Request, path: str):
    """
    Serves files from the /web directory directly, rendering them as templates.
    This allows for dynamic content in static-looking pages.
    """
    try:
        # Use Jinja2Templates to render the file as a template
        return templates.TemplateResponse(f"templates/{path}", {"request": request, "version": VERSION})
    except Exception as e:
        logger.error(f"Error serving web content '{path}': {e}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"File not found: {path}")

@app.get("/index", response_model=List[str])
async def list_indices(current_user: User = Depends(utils.get_current_user_oauth)) -> List[str]:
    return get_all_indices(current_user)


async def query_parquet_and_memory(db_user: User, extended_query: str, start_timestamp: datetime, end_timestamp: datetime, page : int = None, size: int = None):
    """
    Query parquet files with DuckDB SQL syntax.
    :param index: Index (directory) selected by the user
    :param files: Wildcard or file pattern entered by the user
    :param query: SQL query to run on Parquet files
    :return: Query result in JSON format
    """
    db_conn_start = time.time()
    # Connect to DuckDB in-memory
    con = duckdb.connect()
    lock_acquired = False
    try:
        db_conn_time = time.time() - db_conn_start
        logger.debug(f"Connected to DuckDB in {db_conn_time:.2f} seconds.")

        # Capture start time for execution
        overall_start = time.time()
        parse_start = overall_start

        available_indices = get_all_indices(db_user, start_timestamp, end_timestamp)

        # Retrieve the query and commands from the extended query
        parser = MetaCommandParser()
        query, commands = parser.parse(extended_query)

        # Replace wildcard indices with actual index names
        metaquery = MetaQuery(query, available_indices, page, size)
        if metaquery.wildcard:
            logger.info(f"Replaced wildcard indices in query: {metaquery.query()}")

        query_indexes = metaquery.indexes()
        logger.debug(f"Indices found in query: {query_indexes}")

        if not query_indexes:
            logger.error('No valid indices found in query.')
            return JSONResponse(content={"error": "No valid indices found in query. (Use 'SELECT * FROM _indexes' to list available indices.)"})

        manager.process_lock.acquire()
        lock_acquired = True
        logger.info("Processing query Aquired Lock")
        query_with_files = await metaquery.query_with_files(manager, start_timestamp, end_timestamp)

        # Check if any meta indexes from bucket_manager appear in the query
        meta_indexes = get_meta_indexes()
        # Check if any meta indexes from bucket_manager appear in the query (case insensitive)
        has_meta_index = any(re.search(r'\b' + re.escape(meta_index) + r'\b', query_with_files, re.IGNORECASE) for meta_index in meta_indexes)

        # No changes and no meta index found, return error
        if query_with_files == query and not has_meta_index:
            logger.error(NO_VALID_INDEXES_MSG)
            return JSONResponse(content={"error": NO_VALID_INDEXES_MSG})

        logger.info(f"Expanded query to: {query_with_files}")
        parse_time = time.time() - parse_start
        logger.debug(f"Parsed query in {parse_time:.2f} seconds.")
        logger.debug(f"Executing query: {query_with_files}")

        # Execute the query on the Parquet files
        result = ""
        query_start = time.time()
        try:
            # Bind meta tables if neede
            if not metaquery.bind_tables(manager, start_timestamp, end_timestamp, con, available_indices):
                logger.error("Error binding tables! No valid indexes found.")
                return JSONResponse(content={"error": NO_VALID_INDEXES_MSG})
            # Retrieve the result from DuckDB, limit is supposed to be handled by the query
            result = con.execute(query_with_files).fetchall()
        except Exception as e:
            logger.exception(f"Error executing query: {e}")
            logger.error(f"Error executing query: {query_with_files}")
            logger.info(RELEASE_LOCK_INFO_MSG)
            manager.process_lock.release()
            return JSONResponse(content={"error": f"Error executing query: {str(e)}"})
        query_time = time.time() - query_start
        logger.debug(f"Executed query: {query_with_files}")
        logger.info(f"Executed query in {query_time:.2f} seconds.")

        # Format the result as a list of dictionaries
        format_start = time.time()
        column_names = [desc[0] for desc in con.description]  # Extract column names from the cursor description
        formatted_result = [dict(zip(column_names, row)) for row in result]
        format_time = time.time() - format_start
        logger.debug(f"Formatted result in {format_time:.2f} seconds.")

        # Execute any additional commands
        commands_time = 0
        if commands and len(commands) > 0:
            commands_start = time.time()
            for command in commands:
                if command:
                    command_start = time.time()
                    logger.debug(f"Executing command: {command}")
                    previous_length = len(formatted_result)
                    formatted_result = command.execute(formatted_result)
                    current_length = len(formatted_result)
                    logger.debug(f"Command executed: {command}, changed {previous_length} rows to {current_length} rows, in {time.time() - command_start:.2f} seconds.")
            commands_time = time.time() - commands_start
            logger.debug(f"Executed {len(commands)} commands in {commands_time:.2f} seconds.")

        # Remove null columns from the result
        if formatted_result:
            logger.debug("Removing null columns from result.")
            remove_null_cols_start = time.time()
            formatted_result, removed_cols = await remove_null_cols(formatted_result)
            logger.debug(f"Removed {len(removed_cols)} null columns ({removed_cols}), from result in {time.time() - remove_null_cols_start:.2f} seconds.")
        
        # Calculate additional information
        counter_start = time.time()
        logger.debug("Calculating data!")
        number_of_events_returned = len(formatted_result)  # Number of rows returned
        total_number_of_events = count_records_in_parquet_files_from_redis(metaquery.files) + metaquery.count # Total events (files)
        counter_time = time.time() - counter_start
        logger.debug(f"Calculated data in {counter_time:.2f} seconds.")
        overall_time = time.time() - overall_start
    except Exception as e:
        logger.exception(f"Error processing query: {e}")
        if lock_acquired:
            logger.info(RELEASE_LOCK_INFO_MSG)
            manager.process_lock.release()

        return JSONResponse(content={"error": f"Error processing query: {str(e)}"})
    finally:
        con.close()

    try:
        logger.info(RELEASE_LOCK_INFO_MSG)
        manager.process_lock.release()
    except Exception as e:
        logger.exception(f"Error releasing process lock: {e}")

    logger.info(f"Processed query in {overall_time:.2f} seconds, with {number_of_events_returned} events returned out of {total_number_of_events} total events.")
    # Return the query result as JSON
    return JSONResponse(content=jsonable_encoder({
        "result": formatted_result,
        "execution_time": overall_time,
        "parse_time": parse_time,
        "query_time": query_time,
        "format_time": format_time,
        "additional_time": counter_time,
        "commands_time": commands_time,
        "new_connection_time": db_conn_time,
        "number_of_events_returned": number_of_events_returned if formatted_result else 0,
        "total_number_of_events": total_number_of_events if formatted_result else 0
    }))


@app.get("/query")
async def query_data(query: str, start: str, end: str, page : int = None, size: int = None, current_user: User = Depends(utils.get_current_user_oauth)):
    add_user_query(query, current_user.id)
    start_timestamp = smart_strptime(start)
    end_timestamp = smart_strptime(end)

    return await query_parquet_and_memory(current_user, query, start_timestamp, end_timestamp, page, size)



@app.post("/collect")
async def collect(request: Request):
    try:
        data = await request.json()
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON received: {e}")
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Invalid JSON format."})

    for record in data:
        index = record.get("index")
        events = record.get("events", [])
        if not index or not events:
            logger.warning(f"Skipping invalid record: {record}")
            continue

        await manager.process_events(index, events,len(str(events)))

    processed_count = sum(len(record.get("events", [])) for record in data)
    return JSONResponse(content={"message": f"Successfully processed {processed_count} events."}, status_code=status.HTTP_200_OK)

@app.post("/system/shutdown")
async def shutdown():
    await shutdown_tasks()
    return JSONResponse(content={"message": "Shutting down."})

@app.post("/index")
async def index(request: Request):
    start_time = datetime.now(TZ)
    # Push the request into Redis pub/sub queue
    redis_channel = "input"
    data = ""
    try:
        data = await request.body()
        get_redis_pool().lpush(redis_channel, data)
        logger.debug(f"Published data to Redis channel '{redis_channel}'.")
    except Exception as e:
        logger.error(f"Failed to publish data to Redis: {e}")

    duration = datetime.now(TZ) - start_time
    source = request.client.host
    selected_headers = {k: request.headers.get(k, '') for k in ['host', 'x-request-id', 'x-real-ip', 'x-forwarded-for', 'content-length', 'x-original-forwarded-for']}
    msg = f"Indexed {len(data)} bytes from {source} in {duration}. {selected_headers}"
    logger.debug(msg)
    return msg, 200


@app.get("/sources/{index}/last_records")
async def get_last_records(index: str, current_user: User = Depends(utils.get_current_user_oauth)):
    """
    Get the last records from a specific index.
    """
    if not index:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Index parameter is required.")
    if index not in get_all_indices(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not allowed to access this index.")
    last_records = manager.get_last_records(index)
    return JSONResponse(content={"records": last_records})


def filter_indexes_by_user(db_user: User, indexes: List[str]):
    """
    Filter the indexes by the user's permissions.
    """
    if not utils.has_admin_role(db_user):
        available_indices = get_all_indices(db_user)
        if not indexes:
            indexes = available_indices
        else:
            indexes = [index for index in indexes if index in available_indices]

        if not indexes:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not allowed to access some of the requested indexes.")

    return indexes


@app.get("/firehose/create")
async def create_stream(request: Request, index: Optional[List[str]] = Query(None), current_user: User = Depends(utils.get_current_user_oauth)):
    indexes = filter_indexes_by_user(current_user, index or [])
    filters_dict = {}

    # Extract filters from query parameters
    for key, value in request.query_params.items():
        if key.startswith("filter_"):
            field = key[len("filter_"):]
            filters_dict.setdefault(field, []).append(value)

    # check if there is an existing stream with the same indexes and filters, the order of the indexes and filters does not matter
    for stream_id, stream_info in active_streams.items():
        if stream_info['indexes'] == indexes and stream_info['filters'] == filters_dict:
            return {"stream_url": f"/firehose/result/{stream_id}"}  # Return the existing stream URL

    # Generate a new stream ID
    stream_id = str(uuid.uuid4())

    active_streams[stream_id] = {
        "indexes": indexes,
        "filters": filters_dict,
        "channel": f"firehose_channel:{stream_id}",
        "created_at": datetime.now(TZ),
        "created_by": current_user.id
    }

    # Special case for all indexes
    if not indexes:
        indexes = [ACTIVE_STREAM_ALL_INDEXES]

    # Add the new stream to the list of active streams per index
    for index in indexes:
        if index not in active_streams_per_index:
            active_streams_per_index[index] = []
        active_streams_per_index[index].append(stream_id)

    # Save the stream information to Redis
    stream_info_key = stream_key(stream_id)
    stream_info_value = {
        "indexes": json.dumps(indexes),
        "filters": json.dumps(filters_dict)
    }
    get_redis_pool().hmset(stream_info_key, stream_info_value)

    return {"stream_url": f"/firehose/result/{stream_id}"}


def stream_key(stream_id):
    return f"active_streams:{stream_id}"


@app.get("/firehose/result/{stream_id}")
async def custom_stream(stream_id: str, offset: Optional[str] = "LAST", current_user: User = Depends(utils.get_current_user_oauth)):
    stream_info = active_streams.get(stream_id)
    if not stream_info:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Stream not found")

    if not utils.has_admin_role(current_user):
        # Check if the user has access to the requested indexes
        if not stream_info['indexes']:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not allowed to access this stream.")
        available_indices = get_all_indices(current_user)
        stream_indexes = stream_info['indexes']
        for index in stream_indexes:
            if index not in available_indices:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not allowed to access this stream.")

    # Create a unique listener ID
    listener_id = f"{current_user.id}-{str(uuid.uuid4())}"

    logger.debug(f"Starting stream for {stream_id} for listener {listener_id} with offset {offset}.")
    # log the stream info
    logger.debug(f"Stream info: {stream_info}")

    if 'listeners' not in stream_info:
        stream_info['listeners'] = []
    stream_info['listeners'].append(listener_id)

    # Subscribe to the channel
    pubsub = get_redis_pool().pubsub()
    pubsub.subscribe(stream_info['channel'])

    # Return the streaming response
    return StreamingResponse(event_stream(stream_id, stream_info, pubsub, listener_id, offset), media_type="text/event-stream")


async def skip_and_send_existing_data(stream_info: Dict[str, Any], offset):
    # Send existing data
    skip_count = int(offset) if offset and offset.isdigit() else 0
    skip_start = datetime.now(TZ)
    skiped_count = 0
    async for data in send_existing_data(stream_info):
        if skip_count > 0:
            skip_count -= 1
            skiped_count += 1
            continue
        yield f"{data}\n"
    logger.debug(f"Skipped {skiped_count} records in {datetime.now(TZ) - skip_start}.")


async def event_stream(stream_id, stream_info, pubsub, listener_id, offset):
    try:
        old_data_start = datetime.now(TZ)
        if offset is None or offset.upper() != "LAST":
            yield skip_and_send_existing_data(stream_info, offset)
        logger.debug(f"Sent old data in {datetime.now(TZ) - old_data_start}.")

        # Send new real-time data
        logger.debug(f"Starting new data stream for {stream_id}.")
        while True:
            message = pubsub.get_message(ignore_subscribe_messages=True)
            if message:
                data = message['data']
                if data == CLOSE_STREAM_MESSAGE:
                    logger.debug(f"Closing stream for {stream_id} for listener {listener_id}.")
                    yield "event: close\ndata: Stream closed by server\n\n"
                    break
                yield f"{data}\n"
            await asyncio.sleep(0.01)  # Sleep briefly to avoid busy-waiting

    except asyncio.CancelledError:
        yield "event: close\ndata: Stream cancelled by server\n\n"
        raise
    finally:
        # Unsubscribe and remove this listener's ID
        pubsub.unsubscribe(stream_info['channel'])
        if listener_id in stream_info['listeners']:
            stream_info['listeners'].remove(listener_id)


async def send_existing_data_iter(filtered_data, index):
    """
    Send existing data for a specific index.
    """
    filter_start = datetime.now(TZ)
    records = json.loads(filtered_data.to_json(orient='records'))  # Convert to list of dicts
    logger.debug(f"Filtered data in {datetime.now(TZ) - filter_start}.")
    logger.debug(f"Sending {len(records)} records for index {index}.")
    for record in records:  # Yield each record individually
        cleaned_record = {k: v for k, v in record.items() if v is not None}  # Remove null values
        yield json.dumps(cleaned_record)
    logger.debug(f"Sent {len(records)} records for index {index}.")


def send_existing_data_merge(bucket_list):
    """
    Merge all bucket data into a list of tables.
    """
    tables = []
    merge_start = datetime.now(TZ)
    for bucket in bucket_list:
        try:
            tables.append(bucket.data)
        except Exception as e:
            logger.warning(f"Failed to convert bucket {bucket.index} to table: {e}")
    logger.debug(f"Merged {len(tables)} tables in {datetime.now(TZ) - merge_start}.")


async def send_existing_data(stream_info: Dict[str, Any]):
    data_store = manager.buckets
    for index, bucket_list in data_store.items():
        if not stream_info['indexes'] or index in stream_info['indexes']:
            tables = send_existing_data_merge(bucket_list)
            if tables:
                try:
                    fetch_start = datetime.now(TZ)
                    filtered_data = filter_data_with_duckdb(tables, stream_info['filters'])
                    logger.debug(f"Fetched and filtered data in {datetime.now(TZ) - fetch_start}.")
                    if not filtered_data.empty:
                        yield send_existing_data_iter(filtered_data, index)
                except Exception as e:
                    logger.error(f"Error filtering data for index {index}: {e}")


@app.delete("/firehose/{stream_id}")
async def destroy_stream(stream_id: str, current_user: User = Depends(utils.get_current_user_oauth)):
    """
    Destroys the stream with the given ID. Only the creator or an admin can destroy it.
    """
    stream_info = active_streams.get(stream_id)
    if not stream_info:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Stream not found")

    if stream_info['created_by'] != current_user.id and not utils.has_admin_role(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the creator or an admin can destroy this stream")

    # Remove the stream from the active streams
    active_streams.pop(stream_id, None)

    # Send command to close the stream on the client
    get_redis_pool().publish(stream_info['channel'], CLOSE_STREAM_MESSAGE)

    # remove the stream from the active_streams_per_index
    if not stream_info.get("indexes", []) and ACTIVE_STREAM_ALL_INDEXES in active_streams_per_index and stream_id in active_streams_per_index[ACTIVE_STREAM_ALL_INDEXES]:
        active_streams_per_index[ACTIVE_STREAM_ALL_INDEXES].remove(stream_id)
    for index in stream_info.get("indexes", []):
        if stream_id in active_streams_per_index.get(index, []):
            active_streams_per_index[index].remove(stream_id)

    # remove the stream info from Redis
    stream_info_key = stream_key(stream_id)
    get_redis_pool().delete(stream_info_key)

    return {"status": "Stream destroyed"}


@app.get("/firehose/list")
async def list_active_streams(current_user: User = Depends(utils.get_current_user_oauth)):
    """
    Returns a list of active streams with their indexes, filters, and number of active listeners.
    """
    if not utils.has_admin_role(current_user):
        user_indexes = get_all_indices(current_user)
        # Filter active streams by user permissions
        active_streams_filtered = {stream_id: stream_info for stream_id, stream_info in active_streams.items() if
                                    stream_info['indexes'] and all(index in user_indexes for index in stream_info['indexes'])}
    else:
        active_streams_filtered = active_streams
    # Get the list of active streams
    streams_info = []
    for stream_id, stream_info in active_streams_filtered.items():
        streams_info.append({
            "stream_id": stream_id,
            "indexes": stream_info.get("indexes", []),
            "filters": stream_info.get("filters", {}),
            "active_listeners": len(stream_info.get("listeners", [])), # Count active listeners
            "created_by": stream_info.get("created_by"),
            "created_at": stream_info.get("created_at").isoformat() if isinstance(stream_info.get("created_at"), datetime) else stream_info.get("created_at"),
            "channel": stream_info.get("channel"),
            "stream_url": f"/firehose/result/{stream_id}"
        })

    return {"active_streams": streams_info}


@app.get("/bucket")
async def list_buckets():
    bucket_info = []
    for index, bucket_list in manager.buckets.items():
        for bucket in bucket_list:
            info = bucket.get_info()
            bucket_info.append(info)
    return JSONResponse(content={"buckets": bucket_info, "input_queue": get_redis_pool().llen("input")})

@app.get("/bucket/{index}")
async def list_buckets(index: str):
    bucket_info = [bucket.get_info() for bucket in manager.buckets.get(index, [])]
    return JSONResponse(content={"buckets": bucket_info, "input_queue": get_redis_pool().llen("input")})


@app.get("/flush/_all")
async def flush_all():
    data = await manager.flush_all()
    return JSONResponse(content=data["message"], status_code=data["status_code"])

@app.get("/flush/{index}")
async def flush_index(index: str):
    data = await manager.flush_index(index)
    return JSONResponse(content=data["message"], status_code=data["status_code"])

@app.get("/flush/{index}/{bucket_id}")
async def flush_bucket(index: str, bucket_id: str):
    data = await manager.flush_bucket(index, bucket_id)
    return JSONResponse(content=data["message"], status_code=data["status_code"])

# endpoint that returns the version of the collector
@app.get("/version")
async def version():
    return JSONResponse(content={"version": VERSION})

# endpoint that returns the health status of the collector
@app.get("/health")
async def health():
    return JSONResponse(content={"status": "ok"})

def load_active_streams():
    try:
        persisted_data = {}
        for key in get_redis_pool().scan_iter("active_streams:*"):
            stream_id = key.decode('utf-8').split(":")[1]
            stream_info = get_redis_pool().hgetall(key)
            persisted_data[stream_id] = {k: json.loads(v) for k, v in stream_info.items()}

        for stream_id, stream_info in persisted_data.items():
            indexes = stream_info.get("indexes", [])
            active_streams[stream_id] = {
                "indexes": indexes,
                "filters": stream_info.get("filters", {}),
                "channel": f"firehose_channel:{stream_id}",
                "listeners": []             # Start fresh with no listeners
            }

            if len(indexes) == 0:
                if ACTIVE_STREAM_ALL_INDEXES not in active_streams_per_index:
                    active_streams_per_index[ACTIVE_STREAM_ALL_INDEXES] = []
                active_streams_per_index[ACTIVE_STREAM_ALL_INDEXES].append(stream_id)
            for index in indexes:
                if index not in active_streams_per_index:
                    active_streams_per_index[index] = []
                active_streams_per_index[index].append(stream_id)

        logger.info("✅ Active streams loaded successfully.")
    except FileNotFoundError:
        logger.warning("⚠️ No active streams found to load (fresh start).")
    except Exception:
        logger.exception("❌ Error loading active streams")

if __name__ == "__main__":
    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=PORT,
        log_level=LOG_LEVEL.lower(),
        log_config=settings.LOGGING_CONFIG,
        workers=1,
        reload=False,
        timeout_graceful_shutdown=1.0
    )

    server = uvicorn.Server(config)
    try:
        server.run()
    except KeyboardInterrupt:
        logger.info("Shutting down server...")

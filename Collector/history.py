import asyncio
from datetime import datetime
from config import TZ, config_value
from pydantic import BaseModel
import redis
from storage import get_redis_pool


MAX_QUERY_HISTORY : int = config_value("max_query_history", 1000)


class QueryEntry(BaseModel):
    query: str
    last_used: datetime
    times_used: int = 1


last_used = datetime.now(TZ)


def get_user_key(user_id: str):
    return f"query_history:{user_id}"


def add_user_query(query: str, user_id: str):
    global last_used
    key = get_user_key(user_id)
    r = get_redis_pool()
    
    existing_entry = None
    # Get current query entry if it exists
    try:
        existing_entry = r.hget(key, query)
    except redis.ResponseError as e:
        if "WRONGTYPE Operation against a key holding the wrong kind of value" in str(e):
            existing_entry = None
            r.delete(key)
        else:
            raise e
            
    current_time = datetime.now(TZ)

    if existing_entry:
        # Parse existing entry data
        entry_data = QueryEntry.model_validate_json(existing_entry)
        # Update the entry
        entry_data.last_used = current_time
        entry_data.times_used += 1
    else:
        # Create new entry
        entry_data = QueryEntry(
            query=query,
            last_used=current_time
        )

    # Save the entry
    r.hset(key, query, entry_data.model_dump_json())
    last_used = current_time


def delete_user_history(user_id: str):
    """
    Delete all query history for a user.
    """
    key = get_user_key(user_id)
    r = get_redis_pool()
    
    # Delete the user's query history
    r.delete(key)


async def clean_query_history():
    """
    Cleanup query history for all users. For each user, if their history exceeds MAX_QUERY_HISTORY,
    remove the least recently used entries.
    """
    r = get_redis_pool()
    
    # Get all query history keys
    keys = r.keys("query_history:*")
    
    for key in keys:
        # Get all entries for this user
        all_entries = r.hgetall(key)
        
        if len(all_entries) <= MAX_QUERY_HISTORY:
            continue
        
        # Parse entries and sort by last_used
        entries = []
        for query, entry_json in all_entries.items():
            entry = QueryEntry.model_validate_json(entry_json)
            entries.append((query, entry))
        
        # Sort by last_used (oldest first)
        entries.sort(key=lambda x: x[1].last_used)
        
        # Remove oldest entries until we're under the limit
        entries_to_remove = entries[:len(entries) - MAX_QUERY_HISTORY]
        
        if entries_to_remove:
            queries_to_remove = [entry[0] for entry in entries_to_remove]
            r.hdel(key, *queries_to_remove)

        # sleep for a bit to avoid blocking the event loop
        await asyncio.sleep(0.01)


def get_history(user_id: str):
    key = get_user_key(user_id)
    r = get_redis_pool()
    all_entries = r.hgetall(key)
    
    # Parse and sort entries by last_used (most recent first)
    entries = []
    for query, entry_json in all_entries.items():
        entry = QueryEntry.model_validate_json(entry_json)
        entries.append(entry)
    
    # Sort by last_used (newest first)
    entries.sort(key=lambda x: x.last_used, reverse=True)
    
    return entries


def search_history(q: str, user_id: str):
    key = get_user_key(user_id)
    r = get_redis_pool()
    all_entries = r.hgetall(key)
    
    # Parse entries and filter by query string
    matching_entries = []
    for query, entry_json in all_entries.items():
        if q.lower() in query.lower():
            entry = QueryEntry.model_validate_json(entry_json)
            matching_entries.append(entry)
    
    # Sort by last_used (newest first)
    matching_entries.sort(key=lambda x: x.last_used, reverse=True)
    
    return matching_entries


import asyncio
from datetime import datetime
import logging
import re
from bucket_manager import INDEXES_IDX, SCHEMA_IDX, get_meta_indexes
from storage import get_all_indexes_pyarrow, get_buckets_files, get_buckets_info
import pyarrow as pa
import pyarrow.parquet as pq
import duckdb
from config import config_value, TZ
import sqlglot
from sqlglot import exp

logger = logging.getLogger('uvicorn.error')
BUCKET_STORE = config_value("bucket_store", "data")

WILDCARD_TABLE = "WILDCARDTABLE"

class MetaQuery:
    def __init__(self, sql, indexes, page :int = None, size:int = None):
        self.original_query = sql
        self.subqueries = []
        self.available_indexes = {idx.casefold(): idx for idx in indexes}
        self.count = 0
        self.files = [] # files that need to be read
        self.parsed_sql = None # parsed sqlglot query
        self.wildcard = False
        self.page = page
        self.size = size

        # need to check if the query has a wildcard instead of tables, since sqlglot does not support that
        m = re.search(r'(from\s+(\S+))', sql, re.IGNORECASE)
        if not m:
            self._parse_query(sql)
            self.matching_tables = [t.name for t in self.parsed_sql.find_all(exp.Table) if t.name.casefold() in self.available_indexes]

            return  # no FROM clause found
        table_token = m.group(2)
        if '*' not in table_token:
            self._parse_query(sql)
            self.matching_tables = [t.name for t in self.parsed_sql.find_all(exp.Table) if t.name.casefold() in self.available_indexes]
            return  # no wildcard found

        from_token = m.group(1)

        self.wildcard = True

        # Build regex pattern from wildcard in FROM clause.
        pattern_str = "^" + re.escape(table_token).replace(r"\*", ".*") + "$"
        pattern = re.compile(pattern_str, re.IGNORECASE)
        # Wildcard tables must not include meta indexes
        self.matching_tables = [self.available_indexes[t] for t in self.available_indexes if pattern.match(t) and t not in get_meta_indexes()]

        # Change the wildcard into a fixed name that can be changed later
        subquery = re.sub(re.escape(from_token), "from "+WILDCARD_TABLE, sql, count=1)
        self._parse_query(subquery)


    def _parse_query(self, sql):
        self.parsed_sql = sqlglot.parse_one(sql)
        # set limit and offset if page and size are set, and if the query does not already have them
        if self.page is not None and self.size is not None:
            # checi if there is already a limit or offset in the query
            limit = self.parsed_sql.args.get("limit")
            offset = self.parsed_sql.args.get("offset")
            if not limit:
                # set the limit to the query, as there was none before
                self.parsed_sql.set("limit", exp.Limit(
                    expression=exp.Literal.number(self.size)  # LIMIT value
                ))
            if not offset:
                # set the offset to the query, as there was none before
                self.parsed_sql.set("offset", exp.Offset(
                    expression=exp.Literal.number(self.page * self.size)  # OFFSET value
                ))


    def query(self):
        return self.parsed_sql.sql()

    def indexes(self):
        return self.matching_tables

    # Return a pyarrow table with the schemas for each bucket of each index within the start and end timestamp
    def get_schema_table(self, start_timestamp, end_timestamp, user_indexes: list[str] = None) -> pa.Table:

        # Create a list of fields for the schema
        schema = pa.schema([
            pa.field("_bucket_id", pa.string())
        ])
        table = pa.Table.from_pylist([], schema=schema)

        # Add the fields from the schema
        for bucket_info in get_buckets_info(None, start_timestamp, end_timestamp):
            logger.debug(f"Processing bucket_info: {bucket_info}")
            index = bucket_info[b'index'].decode("utf-8")
            if user_indexes is None or index in user_indexes:
                file_path = bucket_info[b'file_location'].decode("utf-8")
                filesize = int(bucket_info[b'uncompressed_file_size'].decode("utf-8"))
                count = int(bucket_info[b'record_count'].decode("utf-8"))
                schema_dict = {
                    "_bucket_id": bucket_info[b'bucket_id'].decode("utf-8"),
                    "_start": bucket_info[b'start_time'].decode("utf-8"),
                    "_end": bucket_info[b'end_time'].decode("utf-8"),
                    "_location": file_path,
                    "__index": index,
                    "_size": filesize,
                    "_count": count
                }
                try:
                    metadata = pq.read_metadata(file_path)
                    # Convert schema to dict
                    for i in range(metadata.num_columns):
                        col_schema = metadata.schema.column(i)
                        schema_dict[col_schema.name] = str(col_schema.physical_type)

                    # Update table with schema information
                    new_data = pa.Table.from_pylist([schema_dict])
                    table = pa.concat_tables([table, new_data], promote_options="default")
                except Exception as e:
                    logger.error(f"Error reading metadata from {file_path}: {e}")
        return table


    def bind_tables(self, manager, start_timestamp : datetime, end_timestamp : datetime, con : duckdb.DuckDBPyConnection, user_indexes: list[str] = None) -> None:
        # bind the tables to the connection
        if SCHEMA_IDX in self.matching_tables:
            schema = self.get_schema_table(start_timestamp, end_timestamp, user_indexes)
            con.register(SCHEMA_IDX, schema)
            logger.debug("Schema table registered")
            self.count += schema.num_rows
        if INDEXES_IDX in self.matching_tables:
            indexes = get_all_indexes_pyarrow(manager, start_timestamp, end_timestamp, user_indexes)
            con.register(INDEXES_IDX, indexes)
            logger.debug("Indexes table registered")
            self.count += indexes.num_rows

    async def query_with_files(self, manager, start_timestamp : datetime, end_timestamp : datetime) -> str:
        # clean the list of files
        self.files = []
        # cycle through the indices in the query and create a table for each, the table name is the index name plus a number
        for index_alias in self.indexes():
            index = index_alias
            index_fold = index.casefold()
            if index_fold in get_meta_indexes():
                # Skip meta indexes
                continue

            # save affected buckets to disk
            await manager.save_buckets(index_fold, start_timestamp, end_timestamp)
            # Get the filtered files for the index, and append them to the list of files
            filtered_files = get_filtered_files(index_fold, start_timestamp, end_timestamp)

            # Change the table in the query for the correct read_parquet function, if not wildcard
            if not self.wildcard:
                read_parquet = self._get_read_parquet(filtered_files)
                self._replace_table(index, read_parquet)

            self.files.extend(filtered_files)

        if self.wildcard:
            # replace the wildcard table with the read_parquet function
            read_parquet = self._get_read_parquet(self.files)
            self._replace_table(WILDCARD_TABLE, read_parquet)

        return self.parsed_sql.sql()


    def _replace_table(self, table, replacement):
        # Parse the replacement string into a real expression (not just a string literal)
        t = table.casefold()
        for atable in self.parsed_sql.find_all(exp.Table):
            if atable.name.casefold() == t:
                atable.replace(replacement)


    def _get_read_parquet(self, files):
        return f"read_parquet({files}, union_by_name = true)"


def get_filtered_files(index, start_timestamp, end_timestamp):
    # Fetch the files for the index stored in redis
    return get_buckets_files(index, start_timestamp, end_timestamp)

# ----------------- Testing -----------------

if __name__ == "__main__":
    available_indices = [
        'pdmfc_fortigate',
        'pdmfc_linux_auth',
        'pdmfc_linux_syslog',
        '_internal'
    ]

    queries = [
        "select _time from pdmfc_*",                      # simple non-count query
        "select count(1) from *fc*",                       # non-grouped count query (using count(1))
        "select _index, count(*) from pdmfc_* group by 1",  # grouped count query without alias
        "select _index, count(*) as sum from pdmfc_* group by 1",  # grouped count query with alias using as
        "SELECT count(*) as sum FROM pdmfc_*",              # non-grouped count query with alias using as
        "SELECT count(*) FROM *",                          # non-grouped count query without alias for all tables
        "select _index, count(*) sum from pdmfc_* group by 1",  # grouped count query with alias without 'as'
        "select count(*) sum, user_id from pdmfc_* group by 2",   # grouped count query with alias without 'as'
        "select count(1) sum, user_id from pdmfc_* group by user_id",  # grouped count query with count(1)
        "select count(1) sum, user_id from pdmfc_* group by 2 order by 2",  # count(1) with positional GROUP BY and ORDER BY
        "select _time, count(1) sum from pdmfc_* group by 1 order by 2 desc",  # two columns, order by aggregated column descending
        "select _index, min(_time), max(_time) from pdmfc_fortig* group by 1"  # aggregate query (min/max)
        "select _index, min(_time) min_time, max(_time) max_time from pdmfc_fortig* group by 1",  # aggregate query (min/max)
        "select max(_time) from * group by _index",     # aggregate query (max)
        "select _index, max(_time) from * group by _index",  # aggregate query (max)
        "SELECT * FROM pdmfc* WHERE timestamp > '2023-01-01'" # simple index without alias
    ]

    for query in queries:
        expanded = MetaQuery(query, available_indices).query()
        print(f"Original Query: {query}")
        print(f"Expanded Query: {expanded}\n")

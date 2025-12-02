from sigma_scheduler.app.sigma_utils import fetch_and_store_sigma_rule, generate_and_store_sql
from sigma_scheduler.app.models import Index, FieldMapping, Alert, SigmaRule
from sigma_scheduler.app.database import SessionLocal
from sqlalchemy import text
from datetime import datetime


def run_demo():
    db = SessionLocal()

    # 1. Create a mock index
    index_name = "windows_logs"
    index = db.query(Index).filter_by(name=index_name).first()
    if not index:
        index = Index(name=index_name, description="Windows logs demo")
        db.add(index)
        db.commit()
        db.refresh(index)
    print(f"✅ Index: {index.name} (ID {index.id})")

    # 2. Import a Sigma rule
    rule = fetch_and_store_sigma_rule(
    url="https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certutil_download.yml?utm_source=chatgpt.com",
    title="Suspicious Certutil (alt rule)"
    )


    # 3. Create field mapping: sigma 'Image' → index 'process_path'
    mapping = FieldMapping(
        index_id=index.id,
        rule_id=rule.id,
        sigma_field="Image",
        index_field="process_path"
    )
    db.add(mapping)
    db.commit()
    print("✅ Field mapping added")

    # 4. Generate SQL from YAML + mapping
    generate_and_store_sql(rule.id, index.name)

    # 5. Insert a mock event into index table
    try:
        db.execute(f"""
        CREATE TABLE IF NOT EXISTS {index.name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            process_path TEXT,
            timestamp TIMESTAMP
        )
        """)
        db.execute(f"""
        INSERT INTO {index.name} (process_path, timestamp)
        VALUES ('C:\\\\Windows\\\\System32\\\\certutil.exe', '{datetime.utcnow()}')
        """)
        db.commit()
        print("✅ Inserted mock event")
    except Exception as e:
        print(f"❌ Failed to insert mock event: {e}")

    # 6. Run SQL rule manually (simulate scheduler)
    rule = db.query(SigmaRule).filter_by(id=rule.id).first()
    result = db.execute(text(rule.sql_query)).fetchall()

    for row in result:
        alert = Alert(
            rule_id=rule.id,
            index_id=index.id,
            matched_fields={"Image": row.process_path},
            raw_event=dict(row._mapping),
            message="Matched via demo_run.py",
            alert_type="sql"
        )
        db.add(alert)
        print("🚨 Alert created from matched rule")

    db.commit()

    # 7. Show stored alerts
    alerts = db.query(Alert).filter_by(rule_id=rule.id).all()
    print(f"\n📋 Found {len(alerts)} alerts:")
    for a in alerts:
        print(f"- {a.timestamp} | {a.message} | {a.raw_event}")

    db.close()


if __name__ == "__main__":
    run_demo()

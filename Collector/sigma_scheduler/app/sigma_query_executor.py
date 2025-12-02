from models import SigmaRuleIndex, SigmaRuleExecution, SigmaRuleExecutionResult
from database import get_db, engine
from datetime import datetime, timezone
import pandas as pd

def execute_query_for_rule(rule_index_id: int):
    db = next(get_db())

    mapping = db.query(SigmaRuleIndex).filter_by(id=rule_index_id).first()

    if not mapping or not mapping.SQL_Query:
        print("❌ No query found for this rule.")
        db.close()
        return

    sql = mapping.SQL_Query
    print(f"▶️ Executing:\n{sql}")

    try:
        # Executing queries with pandas and SQLAlchemy
        # TODO: SQL must be executed against duckdb using MetaCommandParser and MetaQuery
        df = pd.read_sql_query(sql, engine)

        # Entry of execution
        execution = SigmaRuleExecution(
            SigmaRule_index_id=rule_index_id,
            created_at=datetime.now(timezone.utc)(),
            num_rows=len(df)
        )
        db.add(execution)
        db.commit()
        db.refresh(execution)

        print(f"✅ {len(df)} rows matched.")

        # Saving first results
        if not df.empty:
            result = SigmaRuleExecutionResult(
                execution_id=execution.id,
                result_data=df.head(5).to_json(orient="records", indent=2)
            )
            db.add(result)
            db.commit()
            print("✅ Results saved.")

    except Exception as e:
        print(f"❌ Error running query: {e}")

    db.close()

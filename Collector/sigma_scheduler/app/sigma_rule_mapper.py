from database import get_db
from user_management.models import SigmaRuleIndex, SigmaRule
from datetime import datetime, timezone

def map_sigma_rule_to_index(rule_id: int, index_name: str, schedule: str = "*/10 * * * *"):
    db = next(get_db())

    rule = db.query(SigmaRule).filter_by(id=rule_id).first()

    if not rule:
        print(f"❌ Sigma rule with id {rule_id} not found.")
        return

    # Create a new record
    mapping = SigmaRuleIndex(
        title=f"Mapping for {rule.sigmarule_id[:8]}",
        SigmaRule_id=rule.id,
        IndexName=index_name,
        SQL_Query=None,  # θα δημιουργηθεί αργότερα
        schedule=schedule,
        enabled=True,
        last_executed_at=None,
        next_execution_at=None,
        created_at=datetime.now(timezone.utc)(),
        updated_at=datetime.now(timezone.utc)()
    )

    db.add(mapping)
    db.commit()
    db.refresh(mapping)

    print(f"✅ Sigma Rule {rule.sigmarule_id[:8]} mapped to index '{index_name}' with ID {mapping.id}")
    db.close()

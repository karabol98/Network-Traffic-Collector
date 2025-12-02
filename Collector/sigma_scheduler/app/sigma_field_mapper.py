from database import get_db
from user_management.models import SigmaRuleFieldMapping
from datetime import datetime, timezone

def add_field_mapping(rule_index_id: int, sigma_field: str, index_field: str):
    db = next(get_db())

    # Create a mapping record
    mapping = SigmaRuleFieldMapping(
        SigmaRule_index_id=rule_index_id,
        SigmaRule_FieldName=sigma_field,
        Index_FieldName=index_field,
        created_at=datetime.now(timezone.utc)()
    )

    db.add(mapping)
    db.commit()
    db.refresh(mapping)
    print(f"✅ Mapped Sigma field '{sigma_field}' → index field '{index_field}' [Map ID: {mapping.id}]")
    db.close()

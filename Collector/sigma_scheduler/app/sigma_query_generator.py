from sigma_scheduler.app.database import SessionLocal
from sigma_scheduler.app.models import SigmaRule, SigmaRuleIndex, SigmaRuleFieldMapping
import yaml
from sqlalchemy.orm import joinedload

def generate_sql_from_rule(rule_index_id: int):
    db = SessionLocal()

    # Load the mapping with the relationships
    mapping = db.query(SigmaRuleIndex)\
        .options(joinedload(SigmaRuleIndex.sigma_rule))\
        .filter_by(id=rule_index_id).first()

    if not mapping:
        print("❌ Mapping not found.")
        db.close()
        return

    rule = mapping.sigma_rule
    index_name = mapping.IndexName

    field_mappings = db.query(SigmaRuleFieldMapping)\
        .filter_by(SigmaRule_index_id=rule_index_id).all()

    # map Sigma field ➝ Index field
    field_map = {fm.SigmaRule_FieldName: fm.Index_FieldName for fm in field_mappings}

    try:
        rule_dict = yaml.safe_load(rule.sigma_rule_content)
        detection = rule_dict.get("detection", {})
        selection = detection.get("selection", {})

        conditions = []

        for sigma_field, expected_value in selection.items():
            # Support for contains
            if "|contains" in sigma_field:
                real_field = sigma_field.replace("|contains", "").strip()
                if real_field in field_map:
                    index_field = field_map[real_field]
                    conditions.append(f"{index_field} LIKE '%{expected_value}%'")
            else:
                if sigma_field in field_map:
                    index_field = field_map[sigma_field]
                    conditions.append(f"{index_field} = '{expected_value}'")

        where_clause = " AND ".join(conditions)
        sql = f"SELECT * FROM {index_name} WHERE {where_clause};"

        # Save to the board
        mapping.SQL_Query = sql
        db.commit()

        print("✅ SQL generated and stored:")
        print(sql)

    except yaml.YAMLError as e:
        print(f"❌ YAML error: {e}")

    db.close()

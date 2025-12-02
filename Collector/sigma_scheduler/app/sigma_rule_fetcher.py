import os
import yaml
from datetime import datetime, timezone
from database import get_db
from models import SigmaRule

# Path to local sigma_rules folder
SIGMA_RULES_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'sigma_rules')

def fetch_and_store_local_rules():
    db = next(get_db())
    stored_count = 0

    for filename in os.listdir(SIGMA_RULES_DIR):
        if filename.endswith(".yml") or filename.endswith(".yaml"):
            filepath = os.path.join(SIGMA_RULES_DIR, filename)

            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            try:
                parsed = yaml.safe_load(content)
                rule_id = parsed.get("id")
                rule_title = parsed.get("title")

                if not rule_id:
                    print(f"⚠️ Skipping rule (no ID): {filename}")
                    continue

                # Check if rule already exists
                existing = db.query(SigmaRule).filter_by(sigmarule_id=rule_id).first()

                if existing:
                    existing.sigma_rule_content = content
                    existing.updated_at = datetime.now(timezone.utc)()
                    print(f"🔁 Updated rule: {rule_title}")
                else:
                    new_rule = SigmaRule(
                        sigmarule_id=rule_id,
                        sigma_rule_content=content,
                        created_at=datetime.now(timezone.utc)(),
                        updated_at=datetime.now(timezone.utc)()
                    )
                    db.add(new_rule)
                    print(f"✅ Stored new rule: {rule_title}")
                    stored_count += 1

            except yaml.YAMLError as e:
                print(f"❌ YAML error in {filename}: {e}")

    db.commit()
    db.close()
    print(f"📦 Finished. Total new rules stored: {stored_count}")

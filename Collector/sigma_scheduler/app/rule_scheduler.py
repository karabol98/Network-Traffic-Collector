import asyncio
from datetime import datetime
from croniter import croniter
from sqlalchemy.orm import Session
from database import SessionLocal
from models import (
    RuleIndexAssociation, RuleExecutionLog, SigmaRule, SigmaRuleFieldMapping as FieldMapping

)

import yaml
from sigma.parser.collection import SigmaCollectionParser
from sigma.backends.base import SingleTextQueryBackend as TextQueryBackend
from bucket_manager import BucketManager  

# --- Simple SQL Backend ---
class SimpleSQLBackend(TextQueryBackend):
    def convert_condition(self, condition):
        return condition

    def convert_field_eq(self, field, value):
        field = self.field_mapping.get(field, field)
        return f"{field} = '{value}'"

# --- Execution Function ---
async def execute_rule(rule_id: int, index_id: int, assoc_id: int, scheduled_for: datetime, bucket_manager: BucketManager):
    try:
        with SessionLocal() as db:
            rule = db.query(SigmaRule).filter_by(id=rule_id).first()
            mappings = db.query(FieldMapping).filter_by(association_id=assoc_id).all()
            mapping_dict = {m.rule_field: m.index_field for m in mappings}

            if not rule or not rule.content:
                print(f"No content found for rule ID {rule_id}")
                return

            if not mapping_dict:
                print(f"No field mappings found for association ID {assoc_id}")
                return

            parser = SigmaCollectionParser.from_yaml(rule.content)
            backend = SimpleSQLBackend()
            backend.field_mapping = mapping_dict

            queries = backend.convert(parser)
            final_query = queries[0]

            # Get data from manager
            recent_data = bucket_manager.get_last_records(index=str(index_id))

            # Generate alert/event (placeholder)
            alert_event = {
                "_time": datetime.utcnow().isoformat(),
                "rule_id": rule_id,
                "index_id": index_id,
                "query": final_query,
                "sample": recent_data,
            }
            alert_index = f"alerts_rule_{rule_id}"

            # Insert into manager
            await bucket_manager.process_events(alert_index, [alert_event], len(str(alert_event)))

            # Log the result to the DB
            log = db.query(RuleExecutionLog).filter_by(
                association_id=assoc_id,
                scheduled_for=scheduled_for
            ).first()

            if log:
                log.result = f"Stored alert in {alert_index}"
                log.executed_at = datetime.utcnow()
                log.validated_index = str(index_id)
                db.commit()

    except Exception as e:
        print(f"Execution error: {e}")

# --- Main Scheduler Loop ---
async def run_scheduler(bucket_manager: BucketManager):  
    while True:
        now = datetime.utcnow().replace(microsecond=0)

        try:
            with SessionLocal() as db:
                associations = db.query(RuleIndexAssociation).filter_by(active=True).all()

                for assoc in associations:
                    if assoc.schedule:
                        last_log = (
                            db.query(RuleExecutionLog)
                            .filter_by(association_id=assoc.id)
                            .order_by(RuleExecutionLog.scheduled_for.desc())
                            .first()
                        )
                        base_time = last_log.scheduled_for if last_log else datetime.min
                        itr = croniter(assoc.schedule, base_time)
                        next_time = itr.get_next(datetime)

                        if next_time == now:
                            already_logged = (
                                db.query(RuleExecutionLog)
                                .filter_by(association_id=assoc.id, scheduled_for=now)
                                .first()
                            )
                            if not already_logged:
                                print(f"Executing rule {assoc.rule_id} on index {assoc.index_id} at {now}")
                                asyncio.create_task(
                                    execute_rule(assoc.rule_id, assoc.index_id, assoc.id, now, bucket_manager)  # ✅ pass manager here
                                )
                                db.add(RuleExecutionLog(
                                    association_id=assoc.id,
                                    scheduled_for=now
                                ))
                                db.commit()
        except Exception as e:
            print(f"Scheduler error: {e}")
        
        await asyncio.sleep(1)

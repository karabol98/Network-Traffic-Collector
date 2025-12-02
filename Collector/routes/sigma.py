from fastapi import APIRouter
from sigma_scheduler.app.sigma_rule_fetcher import fetch_and_store_local_rules

router = APIRouter()

@router.get("/load")
def load_sigma_rules():
    fetch_and_store_local_rules()
    return {"status": "ok"}


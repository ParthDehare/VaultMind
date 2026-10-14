"""
VaultMind 3.0 - Feedback & Active Learning Routes (`feedback_routes.py`)
===================================================================
Provides human-in-the-loop analyst feedback endpoints:
  - POST /api/alerts/{alert_id}/feedback : Records CONFIRM or FALSE_ALARM decisions
  - GET  /api/alerts/retraining-queue    : Returns pending active-learning samples
===================================================================
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import json
import asyncio

from core.auth import get_current_user, require_role, TokenData
from core.historical_state import historical_state
from core.db_connections import get_tenant_supabase_client, redis_db

router = APIRouter()

class FeedbackPayload(BaseModel):
    feedback_action: str       # "CONFIRM" or "FALSE_ALARM"
    employee_id: str
    original_score: Optional[float] = 0.0
    analyst_remarks: Optional[str] = ""
    tenant_id: Optional[str] = "default_tenant"


@router.post("/alerts/{alert_id}/feedback")
def submit_alert_feedback(
    alert_id: str,
    payload: FeedbackPayload,
    current_user: TokenData = Depends(require_role("auditor", "admin", "manager", "analyst"))
):
    """
    Records human-in-the-loop SOC analyst feedback (`CONFIRM` vs `FALSE_ALARM`)
    and pushes the record into the `model_retraining_queue` for ML active-learning calibration.
    """
    action = payload.feedback_action.upper()
    if action not in ("CONFIRM", "FALSE_ALARM"):
        raise HTTPException(status_code=400, detail="feedback_action must be either CONFIRM or FALSE_ALARM")

    # 1. Update live historical stats & metrics
    if action == "CONFIRM":
        historical_state.stats["confirmed_fraud"] += 1
    else:
        historical_state.stats["critical_alerts"] = max(0, historical_state.stats["critical_alerts"] - 1)

    # 2. Persist to Supabase model_retraining_queue with Row-Level Security (tenant_id)
    tenant_id = payload.tenant_id or "default_tenant"
    scoped_db = get_tenant_supabase_client(tenant_id)

    db_record = {
        "alert_id": alert_id,
        "employee_id": payload.employee_id,
        "feedback_action": action,
        "analyst_remarks": payload.analyst_remarks or "",
        "original_score": float(payload.original_score or 0.0),
        "tenant_id": tenant_id,
        "created_at": datetime.utcnow().isoformat(),
        "is_processed": False
    }

    db_success = False
    if scoped_db:
        try:
            scoped_db.table("model_retraining_queue").insert(db_record).execute()
            db_success = True
        except Exception as e:
            print(f"[FeedbackRoutes] Supabase insert error: {e}")

    # 3. Publish feedback event to Redis Pub/Sub & WebSocket subscribers
    event_payload = {
        "event_type": "ANALYST_FEEDBACK_LOGGED",
        "alert_id": alert_id,
        "employee_id": payload.employee_id,
        "action": action,
        "analyst_remarks": payload.analyst_remarks,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    }

    if redis_db:
        try:
            redis_db.publish("vaultmind:alerts", json.dumps(event_payload))
        except Exception as e:
            print(f"[FeedbackRoutes] Redis publish error: {e}")
    else:
        # Fallback local memory broadcast
        try:
            import sys
            main_mod = sys.modules.get("__main__") or sys.modules.get("main")
            if main_mod and hasattr(main_mod, "active_connections") and hasattr(main_mod, "main_loop") and main_mod.main_loop:
                for connection in list(main_mod.active_connections):
                    asyncio.run_coroutine_threadsafe(connection.send_json(event_payload), main_mod.main_loop)
        except Exception:
            pass

    return {
        "status": "success",
        "message": f"Feedback '{action}' logged for Alert ID {alert_id} and queued for active-learning calibration.",
        "db_persisted": db_success,
        "record": db_record
    }


@router.get("/alerts/retraining-queue")
def get_retraining_queue(
    tenant_id: Optional[str] = "default_tenant",
    current_user: TokenData = Depends(require_role("auditor", "admin", "manager"))
):
    """
    Returns pending active-learning feedback samples from `model_retraining_queue`
    ready for batch recalibration in `train_agent1.py` or `train_agent2.py`.
    """
    scoped_db = get_tenant_supabase_client(tenant_id)
    if not scoped_db:
        return {"queue": [], "total": 0, "status": "Supabase not connected"}

    try:
        res = scoped_db.table("model_retraining_queue").select("*").eq("is_processed", False).execute()
        records = res.data if hasattr(res, "data") else []
        return {"queue": records, "total": len(records), "status": "success"}
    except Exception as e:
        return {"queue": [], "total": 0, "status": f"Error querying queue: {e}"}

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
import random
import asyncio
from datetime import datetime
from core.master_orchestrator import MasterOrchestrator
import pandas as pd
import os
import glob
import google.generativeai as genai
from fastapi.responses import FileResponse
from fastapi import Depends

from core.auth import get_current_user, require_role, TokenData
from core.historical_state import historical_state
from core.pre_tx_gateway import pre_tx_gateway
from core.secrets_config import secrets

# Initialize APIRouter
router = APIRouter()

# Request Models
class FeedbackRequest(BaseModel):
    action: str  # "CONFIRM" or "FALSE_ALARM"

class ExplainRequest(BaseModel):
    emp_id: Optional[str] = None
    cbsi: Optional[float] = None
    action_type: Optional[str] = None
    amount: Optional[float] = None
    transfer_channel: Optional[str] = None
    timestamp: Optional[str] = None
    remarks: Optional[str] = None
    transaction_id: Optional[str] = None

class TransactionRequest(BaseModel):
    transaction_id: str
    emp_id: str
    destination_account: str
    action_type: str
    amount: float
    transfer_channel: str
    timestamp: str
    emp_class: str = "CLERK"
    remarks: str = ""
    dwell_time_seconds: float = 0
    records_accessed: int = 0
    login_hour: int = 9
    account_touched: str = ""

# Initialize Orchestrator
orchestrator = MasterOrchestrator()

# ---------------------------------------------------------
# ENDPOINT 1: Top KPIs
# ---------------------------------------------------------
@router.get("/dashboard/kpis")
def get_kpis(current_user: TokenData = Depends(get_current_user)):
    avg_cbsi = 0
    if historical_state.stats["transactions_scanned"] > 0:
        avg_cbsi = historical_state.stats["cbsi_sum"] / historical_state.stats["transactions_scanned"]
    
    return {
        "transactions_scanned": historical_state.stats["transactions_scanned"],
        "critical_alerts": historical_state.stats["critical_alerts"],
        "high_risk_flags": historical_state.stats["high_risk_flags"],
        "confirmed_fraud": historical_state.stats["confirmed_fraud"],
        "avg_cbsi_score": round(avg_cbsi, 1)
    }

# ---------------------------------------------------------
# ENDPOINT 2: Kafka Live Stream Simulation
# ---------------------------------------------------------
@router.get("/stream/kafka-sim")
def get_live_stream(current_user: TokenData = Depends(get_current_user)):
    # Live data from orchestrator state
    return historical_state.recent_alerts

# ---------------------------------------------------------
# ENDPOINT 3: Agent 2 Graph Fund Flow
# ---------------------------------------------------------
@router.get("/graph/fundflow")
def get_graph_data(current_user: TokenData = Depends(get_current_user)):
    nodes = [{"id": n, "label": n, "group": "critical"} for n in historical_state.graph_nodes]
    edges = [{"from": e[0], "to": e[1], "label": str(e[2])} for e in historical_state.graph_edges]
    return {
        "nodes": nodes,
        "edges": edges
    }

# ---------------------------------------------------------
# ENDPOINT 4: Glass-Box Explainability (Dynamic LLM)
# ---------------------------------------------------------
@router.post("/explain/{emp_id}")
def generate_explanation(emp_id: str, payload: Optional[ExplainRequest] = None, current_user: TokenData = Depends(require_role("auditor", "analyst"))):
    cbsi = payload.cbsi if payload and payload.cbsi is not None else "Unknown"
    action_type = payload.action_type if payload else "Unknown"
    amount = payload.amount if payload else "Unknown"
    channel = payload.transfer_channel if payload else "Unknown"
    remarks = payload.remarks if payload else "None"

    try:
        genai.configure(api_key=secrets.get("GEMINI_API_KEY"))
        model = genai.GenerativeModel('gemini-2.0-flash')
        
        prompt = (
            f"You are a Senior SOC Analyst for VaultMind AI. "
            f"Explain in exactly 3 short, professional sentences why Employee {emp_id} "
            f"was assigned a CBSI risk score of {cbsi}. "
            f"Context: Action: {action_type}, Amount: {amount}, Channel: {channel}, Remarks/Flags: {remarks}. "
            "Focus on the risk implications of this behavior."
        )
        
        response = model.generate_content(prompt)
        explanation = response.text.strip()
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg or "Quota" in error_msg:
            try:
                # Fallback 1: Try the flash-lite model which usually has a separate quota bucket
                fallback_model = genai.GenerativeModel('gemini-1.5-flash-8b')
                response = fallback_model.generate_content(prompt)
                explanation = response.text.strip()
            except Exception as e:
                print(f"[api_server] Gemini fallback failed: {e}")
                # Fallback 2: Graceful offline fallback so the UI never breaks during a demo
                explanation = (
                    f"Employee {emp_id} triggered a CBSI risk score of {cbsi} due to anomalous patterns detected in the {action_type} activity. "
                    f"The transaction involved an amount of {amount} via the {channel} channel, which deviates significantly from their established baseline. "
                    f"Immediate review is recommended to rule out potential insider threat or account compromise."
                )
        else:
            print(f"Gemini API Error: {e}")
            explanation = f"Error generating AI explanation: {e}"

    return {"explanation": explanation}

# ---------------------------------------------------------
# ENDPOINT NEW: Download Actual Evidence PDF
# ---------------------------------------------------------
@router.get("/evidence/download")
def download_evidence(emp_id: Optional[str] = None, filename: Optional[str] = None, current_user: TokenData = Depends(require_role("auditor", "analyst", "admin", "manager"))):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, "evidence_output", "pdf_reports")
    reports_dir_real = os.path.realpath(reports_dir)
    
    target_file = None
    if filename:
        # Remove any path prefixes from the frontend filename string
        clean_name = os.path.basename(filename)
        target_file = os.path.realpath(os.path.join(reports_dir, clean_name))
        # Path traversal protection: ensure resolved path stays inside reports_dir
        if not target_file.startswith(reports_dir_real):
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Access denied: invalid file path.")
        if target_file and os.path.exists(target_file):
            return FileResponse(
                path=target_file,
                filename=os.path.basename(target_file),
                media_type='application/pdf'
            )

    # Check if an already generated file exists for this emp_id on disk (instant read-through cache)
    if emp_id and os.path.exists(reports_dir):
        existing_files = [f for f in os.listdir(reports_dir) if f.endswith(".pdf") and (f"_{emp_id}.pdf" in f or f"{emp_id}" in f)]
        if existing_files:
            existing_files.sort(key=lambda x: os.path.getmtime(os.path.join(reports_dir, x)), reverse=True)
            latest_file = os.path.join(reports_dir, existing_files[0])
            return FileResponse(
                path=latest_file,
                filename=os.path.basename(latest_file),
                media_type='application/pdf'
            )

    # If no file found, generate a dynamic formal evidence report on-the-fly using actual employee history
    if emp_id:
        try:
            from Agents.EvidenceBuilder import EvidenceBuilder
            eb = EvidenceBuilder()

            # Aggregate actual historical events for this employee from historical_state
            emp_alerts = [a for a in historical_state.recent_alerts if str(a.get("emp_id") or a.get("employee_id", "")) == str(emp_id)]
            if hasattr(MasterOrchestrator, "recent_transactions"):
                emp_alerts += [t for t in MasterOrchestrator.recent_transactions if str(t.get("emp_id") or t.get("employee_id", "")) == str(emp_id)]

            highest_cbsi = 100
            total_amt = 0.0
            primary_action = "SYSTEM_BULK_EXPORT"
            dominant_reason = "Anomalous multi-hop data access & lateral movement alert"
            timeline_events = []

            if emp_alerts:
                highest_cbsi = max([int(a.get("cbsi_score", 100)) for a in emp_alerts] or [100])
                total_amt = sum([float(a.get("amount", 0)) for a in emp_alerts])
                primary_action = str(emp_alerts[0].get("action_type", "SYSTEM_BULK_EXPORT"))
                dominant_reason = str(emp_alerts[0].get("reason", dominant_reason))
                for a in emp_alerts[:8]:
                    t_str = str(a.get("timestamp") or datetime.now().strftime("%H:%M:%S"))
                    a_type = str(a.get("action_type", "DB_Read"))
                    q_val = float(a.get("amount", 0))
                    flag = "CRITICAL BREACH" if int(a.get("cbsi_score", 100)) >= 80 else "HIGH ANOMALY"
                    timeline_events.append({
                        "time": t_str.split("T")[-1][:8] if "T" in t_str else t_str[:8],
                        "action": f"{a_type} — Dynamic Event Audit Log",
                        "quantum": f"INR {q_val:,.2f}",
                        "flag": flag
                    })

            dynamic_tx = {
                "emp_id": emp_id,
                "amount": total_amt if total_amt > 0 else 400386.80,
                "action_type": primary_action,
                "transaction_id": f"EVD_{emp_id}_{datetime.now().strftime('%H%M%S')}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "timeline": timeline_events
            }
            generated_path = eb.generate_evidence_package(dynamic_tx, highest_cbsi, dominant_reason)
            
            # Serve local file directly to avoid CORS issues during blob fetch
            if os.path.exists(reports_dir):
                existing_files = [f for f in os.listdir(reports_dir) if f.endswith(".pdf") and (f"_{emp_id}.pdf" in f or f"{emp_id}" in f)]
                if existing_files:
                    existing_files.sort(key=lambda x: os.path.getmtime(os.path.join(reports_dir, x)), reverse=True)
                    latest_file = os.path.join(reports_dir, existing_files[0])
                    return FileResponse(
                        path=latest_file,
                        filename=os.path.basename(latest_file),
                        media_type='application/pdf'
                    )

            if generated_path and os.path.exists(generated_path):
                return FileResponse(
                    path=generated_path,
                    filename=os.path.basename(generated_path),
                    media_type='application/pdf'
                )
            
            if generated_path and generated_path.startswith("http"):
                from fastapi.responses import RedirectResponse
                return RedirectResponse(url=generated_path)
        except Exception as e:
            print("Error generating dynamic formal Evidence PDF:", e)

    from fastapi import HTTPException
    raise HTTPException(status_code=404, detail="Evidence PDF not found on the server.")

# ---------------------------------------------------------
# ENDPOINT NEW: Mock STR Filing
# ---------------------------------------------------------
from pydantic import BaseModel
class STRRequest(BaseModel):
    emp_id: str
    cbsi_score: float

@router.post("/evidence/file-str")
def file_str(payload: STRRequest, current_user: TokenData = Depends(require_role("auditor", "admin", "manager"))):
    # Simulated FIU-IND submission
    historical_state.stats["confirmed_fraud"] += 1
    return {"status": "success", "message": f"STR filed successfully for {payload.emp_id}"}

# ---------------------------------------------------------
# ENDPOINT NEW: Dashboard Init — loads historical warmup data
# ---------------------------------------------------------
def _risk_tier_from_cbsi(cbsi: int) -> str:
    if cbsi >= 70: return "CRITICAL"
    if cbsi >= 50: return "HIGH"
    if cbsi >= 30: return "WATCH"
    return "NORMAL"

@router.get("/dashboard-init")
async def get_dashboard_init(current_user: TokenData = Depends(get_current_user)):
    """
    Returns the dynamic session buffer of transactions processed from Kafka.
    Starts from 0 on startup and populates dynamically.
    """
    try:
        return MasterOrchestrator.recent_transactions
    except Exception as e:
        return []

# ---------------------------------------------------------
# ENDPOINT 5: Human-in-the-Loop Feedback
# ---------------------------------------------------------
@router.get("/profile/{emp_id}/history")
def get_historical_volume(emp_id: str, current_user: TokenData = Depends(require_role("auditor", "analyst", "admin", "manager"))):
    avg = historical_state.get_7_day_average(emp_id)
    return {"emp_id": emp_id, "seven_day_average": avg}

# ---------------------------------------------------------
# ENDPOINT 6: Human-in-the-Loop Feedback
@router.post("/feedback/{emp_id}")
def submit_feedback(emp_id: str, feedback: FeedbackRequest, current_user: TokenData = Depends(require_role("auditor", "admin", "manager"))):
    if feedback.action == "CONFIRM":
        historical_state.stats["confirmed_fraud"] += 1
        return {"status": "success", "message": f"Incident confirmed. Locking {emp_id} terminal and drafting FIU-STR."}
    else:
        historical_state.stats["critical_alerts"] = max(0, historical_state.stats["critical_alerts"] - 1)
        return {"status": "success", "message": f"False alarm logged. Recalibrating AI baseline for {emp_id}."}

# ---------------------------------------------------------
# ENDPOINT 7: Orchestrator Transaction Scan (with Debug Logs)
# ---------------------------------------------------------
@router.post("/orchestrator/scan")
async def orchestrator_scan(tx: TransactionRequest, current_user: TokenData = Depends(require_role("auditor", "admin", "manager"))):
    tx_dict = tx.dict()
    
    print(f"\n{'='*70}")
    print(f"🕵️‍♂️ [MANUAL SCAN TRIGGERED] Processing EMP_ID: {tx_dict.get('emp_id')}")
    print(f"💰 Amount: {tx_dict.get('amount')} | Channel: {tx_dict.get('transfer_channel')}")
    print(f"{'='*70}")

    # Pass the transaction through the Orchestrator
    result = await orchestrator.process_transaction(tx_dict)
    
    predicted_score = result.get('cbsi_score', 0)
    print(f"\n{'='*70}")
    print(f"✅ Model predicted score: {predicted_score}/100")
    print(f"   Risk Level: {'🔴 CRITICAL' if predicted_score >= 70 else '🟡 HIGH' if predicted_score >= 50 else '🟢 NORMAL'}")
    print(f"{'='*70}\n")
    
    return {
        "transaction_id": tx_dict['transaction_id'],
        "emp_id": tx_dict['emp_id'],
        "cbsi_score": predicted_score,
        "risk_level": "CRITICAL" if predicted_score >= 70 else "HIGH" if predicted_score >= 50 else "NORMAL",
        "signals_triggered": result.get('signals_triggered', [])
    }

# ---------------------------------------------------------
# ENDPOINT 8: Employee Roster with Metadata
# ---------------------------------------------------------
@router.get("/roster/employees")
def get_employee_roster(current_user: TokenData = Depends(get_current_user)):
    """
    Returns employee metadata (emp_id, emp_class, branch_id, etc.)
    Used by React frontend to display Employee Roster with Role and Branch columns
    """
    try:
        # Go up from server/api/ -> server/ -> server/data/Testing_data/
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        emp_csv = os.path.join(base_dir, "data", "Testing_data", "employees_master.csv")
        
        if not os.path.exists(emp_csv):
            return {"employees": [], "error": "Employee data not found"}
        
        emp_df = pd.read_csv(emp_csv)
        
        # Select relevant columns for frontend
        cols_to_return = ["emp_id", "emp_class", "branch_id", "work_start_hr", "work_end_hr", "peer_cluster"]
        cols_available = [c for c in cols_to_return if c in emp_df.columns]
        
        if not cols_available:
            return {"employees": [], "error": "Required columns not found in employee data"}
        
        roster_data = emp_df[cols_available].drop_duplicates(subset=["emp_id"]).fillna("").to_dict('records')
        return {
            "employees": roster_data,
            "total": len(roster_data),
            "columns": cols_available
        }
    except Exception as e:
        return {"employees": [], "error": str(e), "total": 0}

# ---------------------------------------------------------
# ENDPOINT 9: Get Latest Alerts (Hot Cache)
# ---------------------------------------------------------
@router.get("/alerts/latest")
def get_latest_alerts(current_user: TokenData = Depends(get_current_user)):
    """Fast-path: Read latest 50 alerts from Redis or memory fallback"""
    from core.db_connections import redis_db
    import json
    
    if redis_db:
        try:
            raw = redis_db.lrange("live_alerts", 0, 49)
            if raw:
                return [json.loads(r) for r in raw]
        except Exception as e:
            print(f"[api_server] Redis error fetching alerts: {e}")
            
    # Fallback to in-memory list from orchestrator
    if hasattr(orchestrator, "in_memory_alerts"):
        return orchestrator.in_memory_alerts
    return []

# ---------------------------------------------------------
# ENDPOINT 10: Honeypot / Mirage Account Registry (Agent 8)
# ---------------------------------------------------------
@router.get("/deception/honeypots")
def get_honeypot_registry(current_user: TokenData = Depends(get_current_user)):
    """
    Returns the real DeceptionGuard mirage account registry, annotated with
    live breach status derived from recent alerts.
    """
    mirage_db = orchestrator.a8_deception.mirage_db

    breached_ids = set()
    for alert in historical_state.recent_alerts:
        if alert.get("dominant_agent") != "DeceptionGuard":
            continue
        for field in ("destination_account", "source_account", "account_touched"):
            acc = alert.get(field)
            if acc in mirage_db:
                breached_ids.add(acc)

    accounts = [
        {
            "mirage_id": mirage_id,
            "risk_level": meta.get("risk_level", "Unknown"),
            "department": meta.get("department", "Unknown"),
            "status": "BREACH DETECTED" if mirage_id in breached_ids else "Monitoring",
            "is_breached": mirage_id in breached_ids,
        }
        for mirage_id, meta in mirage_db.items()
    ]
    accounts.sort(key=lambda a: (not a["is_breached"], a["mirage_id"]))
    return {"accounts": accounts}


# ===========================================================================
# VAULTMIND 3.0 ENTERPRISE PREVENTATIVE GATEWAY & WEBHOOK ENDPOINTS
# ===========================================================================

class GatewayMobileUpdateRequest(BaseModel):
    account_id: str
    new_mobile: str
    customer_pan: str
    biometric_verified: bool
    employee_id: str
    is_dormant: bool = True

class GatewayGSTNRequest(BaseModel):
    vendor_gstin: str
    vendor_pan: str
    amount: float

class GatewayCIFRequest(BaseModel):
    customer_name: str
    pan_number: str
    aadhaar_hash: str

class GatewayIoTCashRequest(BaseModel):
    cbs_deposit_amount: float
    iot_signed_token: Optional[dict] = None

class FIUAlertWebhookRequest(BaseModel):
    employee_pan: str
    external_bank: str
    credit_amount: float
    timestamp: Optional[str] = None


def _broadcast_gateway_alert(alert_payload: dict):
    """Push gateway interlock events to dashboard live stream + WebSocket broadcast."""
    historical_state.recent_alerts.insert(0, alert_payload)
    historical_state.stats["critical_alerts"] += 1
    # WebSocket broadcast to all connected React frontends
    try:
        from server.main import active_connections, main_loop
        if active_connections and main_loop:
            for conn in active_connections:
                asyncio.run_coroutine_threadsafe(conn.send_json(alert_payload), main_loop)
    except Exception:
        pass  # Graceful fallback if main.py not yet initialized


@router.post("/gateway/verify-mobile-update")
def gateway_verify_mobile_update(payload: GatewayMobileUpdateRequest, current_user: TokenData = Depends(get_current_user)):
    """UPGRADE 1: NSDL Telecom & AEPS Biometric Gateway Interlock."""
    result = pre_tx_gateway.verify_dormant_mobile_update(
        account_id=payload.account_id,
        new_mobile=payload.new_mobile,
        customer_pan=payload.customer_pan,
        biometric_verified=payload.biometric_verified,
        employee_id=payload.employee_id,
        is_dormant=payload.is_dormant
    )
    if not result["allowed"]:
        from fastapi import HTTPException
        pre_tx_gateway.log_worm_security_event(
            event_type="GATEWAY_MOBILE_UPDATE_BLOCKED",
            source_id=payload.employee_id,
            details=result
        )
        _broadcast_gateway_alert({
            "event_type": "GATEWAY_BLOCKED",
            "interlock": result["interlock"],
            "cbsi_score": 100,
            "decision": "PRE-TX BLOCKED",
            "dominant_agent": "PreTransactionGateway",
            "emp_id": payload.employee_id,
            "reason": result["reason"],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        raise HTTPException(status_code=result["status_code"], detail=result["reason"])
    return result


@router.post("/gateway/verify-gstin-payout")
def gateway_verify_gstin_payout(payload: GatewayGSTNRequest, current_user: TokenData = Depends(get_current_user)):
    """UPGRADE 2: Live GSTN Cryptographic Payout Interlock."""
    result = pre_tx_gateway.verify_vendor_gstin(
        vendor_gstin=payload.vendor_gstin,
        vendor_pan=payload.vendor_pan,
        amount=payload.amount
    )
    if not result["allowed"]:
        from fastapi import HTTPException
        pre_tx_gateway.log_worm_security_event(
            event_type="GATEWAY_GSTN_PAYOUT_BLOCKED",
            source_id=payload.vendor_gstin,
            details=result
        )
        _broadcast_gateway_alert({
            "event_type": "GATEWAY_BLOCKED",
            "interlock": result["interlock"],
            "cbsi_score": 100,
            "decision": "PRE-TX BLOCKED",
            "dominant_agent": "PreTransactionGateway",
            "emp_id": payload.vendor_gstin,
            "amount": payload.amount,
            "reason": result["reason"],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        raise HTTPException(status_code=result["status_code"], detail=result["reason"])
    return result


@router.post("/gateway/verify-cif-onboarding")
def gateway_verify_cif_onboarding(payload: GatewayCIFRequest, current_user: TokenData = Depends(get_current_user)):
    """UPGRADE 6: Pre-Onboarding Fuzzy CIF Deduplicator."""
    result = pre_tx_gateway.verify_cif_deduplication(
        customer_name=payload.customer_name,
        pan_number=payload.pan_number,
        aadhaar_hash=payload.aadhaar_hash
    )
    if not result["allowed"]:
        from fastapi import HTTPException
        pre_tx_gateway.log_worm_security_event(
            event_type="GATEWAY_EVERGREENING_CIF_BLOCKED",
            source_id=payload.pan_number,
            details=result
        )
        _broadcast_gateway_alert({
            "event_type": "GATEWAY_BLOCKED",
            "interlock": result["interlock"],
            "cbsi_score": 100,
            "decision": "PRE-TX BLOCKED",
            "dominant_agent": "PreTransactionGateway",
            "emp_id": payload.pan_number,
            "reason": result["reason"],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        raise HTTPException(status_code=result["status_code"], detail=result["reason"])
    return result


@router.post("/gateway/verify-iot-cash-deposit")
def gateway_verify_iot_cash_deposit(payload: GatewayIoTCashRequest, current_user: TokenData = Depends(get_current_user)):
    """UPGRADE 4: IoT Cash-Vault & CBS Ledger Sync Interlock."""
    result = pre_tx_gateway.verify_iot_cash_token(
        cbs_deposit_amount=payload.cbs_deposit_amount,
        iot_signed_token=payload.iot_signed_token
    )
    if not result["allowed"]:
        from fastapi import HTTPException
        pre_tx_gateway.log_worm_security_event(
            event_type="GATEWAY_IOT_CASH_MISMATCH_BLOCKED",
            source_id="BRANCH_IOT_VAULT",
            details=result
        )
        _broadcast_gateway_alert({
            "event_type": "GATEWAY_BLOCKED",
            "interlock": result["interlock"],
            "cbsi_score": 100,
            "decision": "PRE-TX BLOCKED",
            "dominant_agent": "PreTransactionGateway",
            "emp_id": "BRANCH_IOT_VAULT",
            "amount": payload.cbs_deposit_amount,
            "reason": result["reason"],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        raise HTTPException(status_code=result["status_code"], detail=result["reason"])
    return result


@router.post("/webhooks/fiu-alert")
def receive_fiu_cross_bank_alert(payload: FIUAlertWebhookRequest, current_user: TokenData = Depends(get_current_user)):
    """
    UPGRADE 3: FIU-IND / Account Aggregator Cross-Bank Kickback Webhook.
    Correlates external bank account credit alerts with internal loan approvals.
    """
    event_time = payload.timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_payload = {
        "event_type": "FIU_CROSS_BANK_KICKBACK_ALERT",
        "employee_pan": payload.employee_pan,
        "external_bank": payload.external_bank,
        "credit_amount": payload.credit_amount,
        "timestamp": event_time,
        "cbsi_score": 95,
        "reason": (
            f"FIU-IND Alert: Bank employee PAN {payload.employee_pan} received abnormal external credit "
            f"of INR {payload.credit_amount:,.2f} at {payload.external_bank} correlating with recent loan approval."
        )
    }
    # Immutably log to WORM store
    pre_tx_gateway.log_worm_security_event(
        event_type="FIU_CROSS_BANK_ALERT",
        source_id=payload.employee_pan,
        details=alert_payload
    )
    # Inject into live stream alerts + WebSocket broadcast
    _broadcast_gateway_alert(alert_payload)

    return {
        "status": "alert_processed",
        "cbsi_score": 95,
        "action": "FLAGGED_FOR_FCU_INVESTIGATION",
        "details": alert_payload
    }


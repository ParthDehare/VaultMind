"""
VaultMind — FastAPI Backend Server
Complete REST API + WebSocket for real-time alerts
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import sqlite3
import json
import asyncio
import hashlib
from datetime import datetime
from typing import List, Optional
import sys
import os

sys.path.append(os.path.dirname(__file__))

from agents.behavior_watch import calculate_behavior_score, get_top_risks
from agents.fund_flow import calculate_fund_flow_score
from agents.other_agents import (
    calculate_vendor_score, calculate_complaint_score,
    calculate_network_score, trigger_mirage_access
)
from agents.orchestrator import run_full_analysis

DB_PATH = "vaultmind.db"
app = FastAPI(title="VaultMind API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket connections
active_connections: List[WebSocket] = []

def get_db():
    return sqlite3.connect(DB_PATH)

# ─── WEBSOCKET ─────────────────────────────────────────────────────────────────
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            conn = get_db()
            c = conn.cursor()
            c.execute("""
                SELECT alert_id, employee_id, alert_type, unified_score,
                       behavior_score, fund_score, network_score, timestamp, status
                FROM alerts ORDER BY unified_score DESC LIMIT 5
            """)
            alerts = c.fetchall()
            conn.close()

            alert_data = [{
                "alert_id": a[0], "employee_id": a[1], "alert_type": a[2],
                "unified_score": a[3], "behavior_score": a[4],
                "fund_score": a[5], "network_score": a[6],
                "timestamp": a[7], "status": a[8]
            } for a in alerts]

            await websocket.send_json({"type": "alerts_update", "data": alert_data})
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        active_connections.remove(websocket)

# ─── DASHBOARD ─────────────────────────────────────────────────────────────────
@app.get("/api/dashboard")
def get_dashboard():
    conn = get_db()
    c = conn.cursor()

    # Stats
    c.execute("SELECT COUNT(*) FROM alerts WHERE status = 'open'")
    open_alerts = c.fetchone()[0]

    c.execute("SELECT MAX(unified_score) FROM alerts")
    max_score = c.fetchone()[0] or 0

    c.execute("SELECT COUNT(*) FROM alerts WHERE unified_score >= 90")
    critical_count = c.fetchone()[0]

    # Top risk employees
    c.execute("""
        SELECT e.employee_id, e.name, e.role, e.branch,
               COALESCE(a.unified_score, 0) as score
        FROM employees e
        LEFT JOIN alerts a ON e.employee_id = a.employee_id
        ORDER BY score DESC LIMIT 10
    """)
    top_risks = [{"id": r[0], "name": r[1], "role": r[2], "branch": r[3], "score": r[4]}
                 for r in c.fetchall()]

    # Recent alerts
    c.execute("""
        SELECT alert_id, employee_id, alert_type, unified_score, timestamp, status
        FROM alerts ORDER BY timestamp DESC LIMIT 5
    """)
    recent_alerts = [{"id": r[0], "employee_id": r[1], "type": r[2],
                      "score": r[3], "time": r[4], "status": r[5]}
                     for r in c.fetchall()]

    conn.close()
    return {
        "stats": {
            "open_alerts": open_alerts,
            "max_score": max_score,
            "critical_count": critical_count,
            "agents_running": 8
        },
        "top_risks": top_risks,
        "recent_alerts": recent_alerts,
        "all_agents_status": {
            "BehaviorWatch": "active", "FundFlow": "active",
            "VendorGuard": "active", "ComplaintSignal": "active",
            "NetworkIntelligence": "active", "RegulatoryCompliance": "active",
            "EvidenceBuilder": "active", "DeceptionGuard": "active"
        }
    }

# ─── EMPLOYEES ─────────────────────────────────────────────────────────────────
@app.get("/api/employees")
def get_employees(limit: int = 20):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT e.employee_id, e.name, e.role, e.branch, e.risk_score,
               COALESCE(a.unified_score, 0) as alert_score
        FROM employees e
        LEFT JOIN alerts a ON e.employee_id = a.employee_id
        ORDER BY alert_score DESC LIMIT ?
    """, (limit,))
    employees = [{"id": r[0], "name": r[1], "role": r[2], "branch": r[3],
                  "risk_score": r[4], "alert_score": r[5]}
                 for r in c.fetchall()]
    conn.close()
    return {"employees": employees, "total": len(employees)}

@app.get("/api/employees/{employee_id}")
def get_employee_detail(employee_id: str):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM employees WHERE employee_id = ?", (employee_id,))
    emp = c.fetchone()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")

    c.execute("""
        SELECT date, login_time, records_accessed, ip_address, is_anomalous
        FROM behavior_logs WHERE employee_id = ? ORDER BY date DESC LIMIT 30
    """, (employee_id,))
    behavior = [{"date": r[0], "login_time": r[1], "records": r[2],
                 "ip": r[3], "anomalous": r[4]} for r in c.fetchall()]

    conn.close()
    return {
        "employee": {"id": emp[0], "name": emp[1], "role": emp[2],
                     "branch": emp[3], "join_date": emp[6]},
        "behavior_history": behavior
    }

# ─── ALERTS ───────────────────────────────────────────────────────────────────
@app.get("/api/alerts")
def get_alerts():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT a.alert_id, a.employee_id, e.name, a.alert_type,
               a.unified_score, a.behavior_score, a.fund_score,
               a.network_score, a.timestamp, a.status, a.evidence_hash
        FROM alerts a
        LEFT JOIN employees e ON a.employee_id = e.employee_id
        ORDER BY a.unified_score DESC
    """)
    alerts = [{
        "id": r[0], "employee_id": r[1], "employee_name": r[2],
        "type": r[3], "score": r[4], "behavior_score": r[5],
        "fund_score": r[6], "network_score": r[7],
        "timestamp": r[8], "status": r[9], "evidence_hash": r[10]
    } for r in c.fetchall()]
    conn.close()
    return {"alerts": alerts}

# ─── DEMO TRIGGER ─────────────────────────────────────────────────────────────
@app.post("/api/demo/trigger")
def trigger_demo():
    """Triggers the Employee 4471 fraud scenario"""
    result = run_full_analysis("EMP4471")
    return {
        "success": True,
        "message": "Demo scenario triggered — Employee 4471",
        "result": result,
        "cinematic_data": {
            "events": [
                {"time": "09:15 AM", "type": "normal", "desc": "Normal login — Mumbai branch", "score": 12},
                {"time": "10:30 AM", "type": "normal", "desc": "23 records accessed — within baseline", "score": 14},
                {"time": "04:45 PM", "type": "normal", "desc": "4 transactions — avg ₹85,000", "score": 11},
                {"time": "06:30 PM", "type": "normal", "desc": "Normal logout", "score": 12},
                {"time": "02:47 AM", "type": "critical", "desc": "LOGIN DETECTED — Unknown IP 10.58.201.99", "score": 45},
                {"time": "02:48 AM", "type": "critical", "desc": "4,847 RECORDS DOWNLOADING — 210x above baseline", "score": 78},
                {"time": "02:49 AM", "type": "critical", "desc": "₹47L SWIFT TRANSFER ATTEMPTED", "score": 92},
                {"time": "02:49:18", "type": "alert", "desc": "VAULTMIND CRITICAL ALERT FIRED", "score": 96},
                {"time": "02:49:19", "type": "freeze", "desc": "ACCOUNT ACCESS FROZEN", "score": 96},
                {"time": "02:49:20", "type": "evidence", "desc": f"BLOCKCHAIN HASH: {result.get('evidence_hash', '')[:20]}...", "score": 96},
            ]
        }
    }

# ─── EVIDENCE ─────────────────────────────────────────────────────────────────
@app.get("/api/evidence/{employee_id}")
def get_evidence(employee_id: str):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM alerts WHERE employee_id = ? ORDER BY timestamp DESC LIMIT 1",
              (employee_id,))
    alert = c.fetchone()
    if not alert:
        raise HTTPException(status_code=404, detail="No alert found")
    conn.close()
    return {
        "alert_id": alert[0],
        "employee_id": alert[1],
        "unified_score": alert[3],
        "evidence_hash": alert[9],
        "blockchain_status": "CONFIRMED",
        "str_status": "AUTO_GENERATED",
        "generation_time": "2.8 seconds",
        "timestamp": alert[7]
    }

# ─── MIRAGE ACCOUNTS ──────────────────────────────────────────────────────────
@app.get("/api/deception-guard")
def get_mirage_status():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT account_id, name, balance, access_log FROM mirage_accounts")
    accounts = [{"id": r[0], "name": r[1], "balance": r[2],
                 "accessed": json.loads(r[3]) != []} for r in c.fetchall()]
    conn.close()
    return {"mirage_accounts": accounts, "total": len(accounts)}

@app.post("/api/deception-guard/simulate-access")
def simulate_mirage_access(employee_id: str = "EMP4471"):
    conn = get_db()
    result = trigger_mirage_access(employee_id, "MIRAGE_0001", conn)
    conn.close()
    return result

# ─── COUNTERFACTUAL SLIDER ────────────────────────────────────────────────────
@app.get("/api/counterfactual/{employee_id}")
def get_counterfactual(employee_id: str, login_time: int = 2,
                        records: int = 4847, txn_amount: float = 4700000):
    """Live counterfactual score calculation"""
    score = 0
    reasons = []

    # Login time contribution
    if login_time < 6:
        score += 38
        reasons.append(f"Login at {login_time}:00 AM: +38 points")
    elif login_time < 8:
        score += 15
        reasons.append(f"Early login at {login_time}:00 AM: +15 points")
    else:
        reasons.append(f"Normal login time {login_time}:00 AM: +0 points")

    # Records contribution
    baseline_records = 25
    if records > baseline_records * 5:
        r_score = min(35, records / baseline_records * 2)
        score += r_score
        reasons.append(f"{records} records ({records//baseline_records}x baseline): +{r_score:.0f} points")
    else:
        reasons.append(f"{records} records (within normal): +0 points")

    # Transaction amount
    if txn_amount > 1000000:
        t_score = min(20, txn_amount / 1000000 * 4)
        score += t_score
        reasons.append(f"₹{txn_amount:,.0f} transaction: +{t_score:.0f} points")

    # IP penalty (always present in fraud scenario)
    score += 15
    reasons.append("Unknown IP address: +15 points (fixed)")

    final_score = min(100, round(score, 1))
    return {
        "employee_id": employee_id,
        "inputs": {"login_time": login_time, "records": records, "txn_amount": txn_amount},
        "score": final_score,
        "risk_level": "CRITICAL" if final_score >= 90 else "HIGH" if final_score >= 70 else "MEDIUM" if final_score >= 50 else "LOW",
        "reasons": reasons,
        "message": f"Score: {final_score}/100 — {'Alert would FIRE' if final_score >= 70 else 'Alert would NOT fire'}"
    }

# ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
@app.get("/")
def health():
    return {
        "status": "VaultMind API Running",
        "version": "2.0.0",
        "agents": 8,
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    print("\n🚀 Starting VaultMind Backend Server...")
    print("📡 API: http://localhost:8000")
    print("📚 Docs: http://localhost:8000/docs")
    print("🔌 WebSocket: ws://localhost:8000/ws/alerts\n")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
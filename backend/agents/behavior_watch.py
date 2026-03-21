"""
VaultMind — Agent 1: BehaviorWatch
Personal AI baseline per employee using Isolation Forest
Alerts on deviation from THEIR normal — not global rules
"""

import sqlite3
import numpy as np
import json
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta

DB_PATH = "vaultmind.db"

def get_employee_baseline(employee_id: str, conn) -> dict:
    c = conn.cursor()
    c.execute("""
        SELECT login_time, logout_time, records_accessed
        FROM behavior_logs
        WHERE employee_id = ? AND is_anomalous = 0
        ORDER BY date DESC LIMIT 60
    """, (employee_id,))
    rows = c.fetchall()
    if not rows:
        return None
    return {
        "avg_login": np.mean([r[0] for r in rows]),
        "avg_logout": np.mean([r[1] for r in rows]),
        "avg_records": np.mean([r[2] for r in rows]),
        "std_login": np.std([r[0] for r in rows]) or 1,
        "std_records": np.std([r[2] for r in rows]) or 1,
        "samples": rows
    }

def train_isolation_forest(samples: list) -> IsolationForest:
    X = np.array([[s[0], s[1], s[2]] for s in samples])
    model = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
    model.fit(X)
    return model

def calculate_behavior_score(employee_id: str, conn) -> dict:
    c = conn.cursor()

    # Get employee baseline
    baseline = get_employee_baseline(employee_id, conn)
    if not baseline:
        return {"score": 0, "reason": "Insufficient data", "employee_id": employee_id}

    # Get today's behavior
    today = datetime.now().strftime('%Y-%m-%d')
    c.execute("""
        SELECT login_time, logout_time, records_accessed,
               ip_address, modules_used, is_anomalous, anomaly_type
        FROM behavior_logs
        WHERE employee_id = ? AND date = ?
        ORDER BY id DESC LIMIT 1
    """, (employee_id, today))
    today_log = c.fetchone()

    if not today_log:
        return {"score": 5, "reason": "No activity today", "employee_id": employee_id}

    login_h, logout_h, records, ip, modules, is_anom, anom_type = today_log
    modules_list = json.loads(modules) if modules else []

    # Train Isolation Forest
    model = train_isolation_forest(baseline["samples"])
    current = np.array([[login_h, logout_h, records]])
    isolation_score = model.score_samples(current)[0]

    # Convert to 0-100 risk score
    raw_score = max(0, min(100, (-isolation_score + 0.5) * 100))

    # Deviation multipliers
    login_deviation = abs(login_h - baseline["avg_login"]) / baseline["std_login"]
    record_deviation = abs(records - baseline["avg_records"]) / baseline["std_records"]

    # Off-hours penalty (login between midnight and 6am)
    off_hours_penalty = 35 if login_h < 6 else 0

    # Bulk download penalty
    bulk_penalty = 30 if records > baseline["avg_records"] * 5 else 0

    # Unknown IP penalty
    ip_penalty = 20 if ip.startswith("10.") or ip.startswith("172.") else 0

    # Unauthorized module penalty
    sensitive_modules = {"SWIFT_GATEWAY", "BULK_EXPORT", "ADMIN_PANEL"}
    module_penalty = 15 if any(m in sensitive_modules for m in modules_list) else 0

    # Final score
    final_score = min(100, raw_score + off_hours_penalty + bulk_penalty + ip_penalty + module_penalty)

    # Build reason
    reasons = []
    if off_hours_penalty: reasons.append(f"Login at {login_h}:00 AM (off-hours)")
    if bulk_penalty: reasons.append(f"{records} records ({record_deviation:.1f}x above baseline)")
    if ip_penalty: reasons.append(f"Unknown IP: {ip}")
    if module_penalty: reasons.append(f"Sensitive modules: {', '.join(modules_list)}")

    return {
        "employee_id": employee_id,
        "score": round(final_score, 1),
        "baseline_avg_login": round(baseline["avg_login"], 1),
        "baseline_avg_records": round(baseline["avg_records"], 1),
        "today_login": login_h,
        "today_records": records,
        "login_deviation": round(login_deviation, 2),
        "record_deviation": round(record_deviation, 2),
        "ip_address": ip,
        "modules_used": modules_list,
        "reasons": reasons,
        "risk_level": "CRITICAL" if final_score >= 90 else "HIGH" if final_score >= 70 else "MEDIUM" if final_score >= 50 else "LOW",
        "timestamp": datetime.now().isoformat()
    }

def run_behavior_watch(employee_ids: list = None) -> list:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    if not employee_ids:
        c.execute("SELECT employee_id FROM employees")
        employee_ids = [r[0] for r in c.fetchall()]

    results = []
    for emp_id in employee_ids:
        result = calculate_behavior_score(emp_id, conn)
        results.append(result)

        # Update risk score in DB
        c.execute("UPDATE employees SET risk_score = ? WHERE employee_id = ?",
                  (result["score"], emp_id))

    conn.commit()
    conn.close()
    return results

def get_top_risks(limit: int = 10) -> list:
    results = run_behavior_watch()
    return sorted(results, key=lambda x: x["score"], reverse=True)[:limit]

if __name__ == "__main__":
    print("\n🔍 BehaviorWatch Agent Starting...\n")
    conn = sqlite3.connect(DB_PATH)
    result = calculate_behavior_score("EMP4471", conn)
    conn.close()
    print(f"Employee 4471 Score: {result['score']}/100")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Reasons: {result['reasons']}")
    print("\n✅ BehaviorWatch Agent: OPERATIONAL")
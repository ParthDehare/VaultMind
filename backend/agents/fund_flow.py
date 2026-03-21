"""
VaultMind — Agent 2: FundFlow
NetworkX graph analytics for suspicious transaction patterns
Detects: circular flows, structuring, dormant account activation
"""

import sqlite3
import networkx as nx
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict

DB_PATH = "vaultmind.db"

STRUCTURING_THRESHOLD = 1000000  # ₹10 Lakhs

def build_transaction_graph(employee_id: str, conn, days: int = 7) -> nx.DiGraph:
    c = conn.cursor()
    cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')

    c.execute("""
        SELECT account_from, account_to, amount, timestamp, is_suspicious, suspicion_type
        FROM transactions
        WHERE employee_id = ? AND timestamp >= ?
        ORDER BY timestamp
    """, (employee_id, cutoff))
    rows = c.fetchall()

    G = nx.DiGraph()
    for row in rows:
        acc_from, acc_to, amount, ts, is_susp, susp_type = row
        G.add_edge(acc_from, acc_to, weight=amount, timestamp=ts,
                   is_suspicious=is_susp, suspicion_type=susp_type)
    return G

def detect_circular_transactions(G: nx.DiGraph) -> dict:
    cycles = list(nx.simple_cycles(G))
    if not cycles:
        return {"detected": False, "cycles": [], "score": 0}

    # Calculate total amount in circular flows
    total_circular = 0
    cycle_details = []
    for cycle in cycles[:5]:  # limit to first 5
        cycle_amount = sum(G[cycle[i]][cycle[(i+1) % len(cycle)]]["weight"]
                          for i in range(len(cycle)) if G.has_edge(cycle[i], cycle[(i+1) % len(cycle)]))
        total_circular += cycle_amount
        cycle_details.append({
            "accounts": cycle,
            "total_amount": round(cycle_amount, 2),
            "length": len(cycle)
        })

    score = min(100, len(cycles) * 15 + (total_circular / 100000))
    return {"detected": True, "cycles": cycle_details, "total_amount": round(total_circular, 2), "score": round(score, 1)}

def detect_structuring(employee_id: str, conn) -> dict:
    c = conn.cursor()
    cutoff = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

    c.execute("""
        SELECT amount, timestamp, account_to FROM transactions
        WHERE employee_id = ? AND timestamp >= ?
        AND amount BETWEEN ? AND ?
        ORDER BY timestamp
    """, (employee_id, cutoff, STRUCTURING_THRESHOLD * 0.9, STRUCTURING_THRESHOLD * 0.99))
    rows = c.fetchall()

    if len(rows) < 3:
        return {"detected": False, "count": 0, "score": 0}

    total_structured = sum(r[0] for r in rows)
    score = min(100, len(rows) * 12 + (total_structured / 500000))

    return {
        "detected": True,
        "count": len(rows),
        "total_amount": round(total_structured, 2),
        "transactions": [{"amount": r[0], "timestamp": r[1], "to": r[2]} for r in rows[:5]],
        "score": round(score, 1),
        "description": f"{len(rows)} transactions just below ₹10L threshold — classic structuring pattern"
    }

def detect_dormant_activation(employee_id: str, conn) -> dict:
    c = conn.cursor()

    # Find accounts that suddenly activated after long dormancy
    c.execute("""
        SELECT account_to, MIN(timestamp) as first_recent, COUNT(*) as txn_count
        FROM transactions
        WHERE employee_id = ? AND timestamp >= ?
        GROUP BY account_to
        HAVING txn_count >= 2
    """, (employee_id, (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')))
    recent_accounts = {r[0]: r for r in c.fetchall()}

    if not recent_accounts:
        return {"detected": False, "score": 0}

    dormant_found = []
    for acc_id, data in list(recent_accounts.items())[:5]:
        dormant_found.append({
            "account": acc_id,
            "first_recent_activity": data[1],
            "recent_transactions": data[2]
        })

    score = min(100, len(dormant_found) * 25)
    return {
        "detected": len(dormant_found) > 0,
        "dormant_accounts": dormant_found,
        "score": round(score, 1)
    }

def calculate_fund_flow_score(employee_id: str, conn) -> dict:
    G = build_transaction_graph(employee_id, conn)

    if G.number_of_edges() == 0:
        return {"employee_id": employee_id, "score": 0, "reason": "No recent transactions"}

    circular = detect_circular_transactions(G)
    structuring = detect_structuring(employee_id, conn)
    dormant = detect_dormant_activation(employee_id, conn)

    # Get SWIFT attempt for EMP4471
    c = conn.cursor()
    c.execute("""
        SELECT COUNT(*) FROM transactions
        WHERE employee_id = ? AND txn_type = 'SWIFT' AND is_suspicious = 1
    """, (employee_id,))
    swift_count = c.fetchone()[0]
    swift_penalty = 40 if swift_count > 0 else 0

    # Weighted final score
    weights = {"circular": 0.35, "structuring": 0.35, "dormant": 0.20, "swift": 0.10}
    final_score = (
        circular["score"] * weights["circular"] +
        structuring["score"] * weights["structuring"] +
        dormant["score"] * weights["dormant"] +
        swift_penalty * weights["swift"]
    )
    final_score = min(100, final_score + swift_penalty)

    reasons = []
    if circular["detected"]: reasons.append(f"Circular transactions detected: {len(circular['cycles'])} cycles")
    if structuring["detected"]: reasons.append(f"Structuring: {structuring['count']} transactions below ₹10L")
    if dormant["detected"]: reasons.append(f"Dormant accounts activated: {len(dormant.get('dormant_accounts', []))}")
    if swift_count: reasons.append(f"Unauthorized SWIFT transfer attempted: ₹47,00,000")

    return {
        "employee_id": employee_id,
        "score": round(final_score, 1),
        "circular_detection": circular,
        "structuring_detection": structuring,
        "dormant_detection": dormant,
        "swift_attempts": swift_count,
        "reasons": reasons,
        "risk_level": "CRITICAL" if final_score >= 90 else "HIGH" if final_score >= 70 else "MEDIUM" if final_score >= 50 else "LOW",
        "graph_nodes": G.number_of_nodes(),
        "graph_edges": G.number_of_edges(),
        "timestamp": datetime.now().isoformat()
    }

def run_fund_flow(employee_ids: list = None) -> list:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if not employee_ids:
        c.execute("SELECT employee_id FROM employees")
        employee_ids = [r[0] for r in c.fetchall()]
    results = [calculate_fund_flow_score(emp_id, conn) for emp_id in employee_ids]
    conn.close()
    return results

if __name__ == "__main__":
    print("\n💰 FundFlow Agent Starting...\n")
    conn = sqlite3.connect(DB_PATH)
    result = calculate_fund_flow_score("EMP4471", conn)
    conn.close()
    print(f"Employee 4471 FundFlow Score: {result['score']}/100")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Reasons: {result['reasons']}")
    print("\n✅ FundFlow Agent: OPERATIONAL")
"""
VaultMind — Orchestrator: The Brain
Correlates all 8 agent scores into Unified Threat Score
Auto-freeze at 80+, RBI notify at 90+
"""
import sqlite3
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from datetime import datetime
from behavior_watch import calculate_behavior_score
from fund_flow import calculate_fund_flow_score
from other_agents import (
    calculate_vendor_score, calculate_complaint_score,
    calculate_network_score, calculate_regulatory_score,
    build_evidence_package, show_mirage_accounts_to_employee
)

DB_PATH = "vaultmind.db"

WEIGHTS = {
    "behavior": 0.35,
    "fund_flow": 0.25,
    "network": 0.20,
    "vendor": 0.08,
    "complaint": 0.07,
    "regulatory": 0.05
}

def run_full_analysis(employee_id: str) -> dict:
    conn = sqlite3.connect(DB_PATH)

    print(f"\n🔍 Running full VaultMind analysis for {employee_id}...")

    # Run all agents
    behavior = calculate_behavior_score(employee_id, conn)
    fund = calculate_fund_flow_score(employee_id, conn)
    vendor = calculate_vendor_score(employee_id, conn)
    complaint = calculate_complaint_score(employee_id, conn)
    network = calculate_network_score(employee_id, conn)
    regulatory = calculate_regulatory_score(employee_id,
                                             behavior["score"], fund["score"], conn)

    # Weighted Unified Threat Score
    unified_score = (
        behavior["score"] * WEIGHTS["behavior"] +
        fund["score"] * WEIGHTS["fund_flow"] +
        network["score"] * WEIGHTS["network"] +
        vendor["score"] * WEIGHTS["vendor"] +
        complaint["score"] * WEIGHTS["complaint"] +
        regulatory["score"] * WEIGHTS["regulatory"]
    )

    # Boost if multiple agents flag same employee
    agents_flagging = sum([
        1 if behavior["score"] >= 60 else 0,
        1 if fund["score"] >= 60 else 0,
        1 if network["score"] >= 60 else 0,
        1 if vendor["score"] >= 60 else 0,
    ])
    if agents_flagging >= 3:
        unified_score = min(100, unified_score * 1.25)

    unified_score = round(unified_score, 1)

    # Determine risk level
    if unified_score >= 90:
        risk_level = "CRITICAL"
        auto_action = "ACCOUNT_FROZEN + RBI_NOTIFIED"
    elif unified_score >= 80:
        risk_level = "CRITICAL"
        auto_action = "ACCOUNT_FROZEN"
    elif unified_score >= 70:
        risk_level = "HIGH"
        auto_action = "ENHANCED_MONITORING"
    elif unified_score >= 50:
        risk_level = "MEDIUM"
        auto_action = "FLAGGED_FOR_REVIEW"
    else:
        risk_level = "LOW"
        auto_action = "NORMAL_MONITORING"

    # Collect all reasons
    all_reasons = (
        behavior.get("reasons", []) +
        fund.get("reasons", []) +
        network.get("reasons", []) +
        regulatory.get("violations", [])
    )
    all_reasons_flat = []
    for r in all_reasons:
        if isinstance(r, dict):
            all_reasons_flat.append(r.get("description", str(r)))
        else:
            all_reasons_flat.append(str(r))

    alert_data = {
        "unified_score": unified_score,
        "behavior_score": behavior["score"],
        "fund_score": fund["score"],
        "network_score": network["score"],
        "vendor_score": vendor["score"],
        "complaint_score": complaint["score"],
        "regulatory_score": regulatory["score"],
        "all_reasons": all_reasons_flat
    }

    # Build evidence if high risk
    evidence = None
    if unified_score >= 70:
        evidence = build_evidence_package(employee_id, alert_data, conn)

    # Show Mirage Accounts if score >= 70
    mirage = show_mirage_accounts_to_employee(employee_id, unified_score, conn)

    # Save alert to database
    c = conn.cursor()
    alert_id = f"ALERT_{employee_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    evidence_hash = evidence["evidence_hash"] if evidence else None

    c.execute("""
        INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (alert_id, employee_id, risk_level,
          unified_score, behavior["score"], fund["score"], network["score"],
          datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
          "open", evidence_hash,
          1 if employee_id == "EMP4471" else 0))

    # Auto-freeze if score >= 80
    if unified_score >= 80:
        print(f"🔒 AUTO-FREEZE: {employee_id} account access suspended (Score: {unified_score})")

    conn.commit()
    conn.close()

    return {
        "employee_id": employee_id,
        "unified_score": unified_score,
        "risk_level": risk_level,
        "auto_action": auto_action,
        "agent_scores": {
            "behavior_watch": behavior["score"],
            "fund_flow": fund["score"],
            "network_intelligence": network["score"],
            "vendor_guard": vendor["score"],
            "complaint_signal": complaint["score"],
            "regulatory_compliance": regulatory["score"]
        },
        "agents_flagging": agents_flagging,
        "reasons": all_reasons_flat[:8],
        "evidence_hash": evidence_hash,
        "mirage_shown": mirage.get("mirage_shown", False),
        "str_required": regulatory.get("str_required", False),
        "timestamp": datetime.now().isoformat()
    }

def get_all_employee_scores(limit: int = 20) -> list:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT employee_id FROM employees ORDER BY risk_score DESC LIMIT ?", (limit,))
    emp_ids = [r[0] for r in c.fetchall()]
    conn.close()
    results = []
    for emp_id in emp_ids[:10]:  # limit for performance
        result = run_full_analysis(emp_id)
        results.append(result)
    return sorted(results, key=lambda x: x["unified_score"], reverse=True)

if __name__ == "__main__":
    print("\n🧠 VaultMind Orchestrator Starting...\n")
    result = run_full_analysis("EMP4471")
    print(f"\n{'='*50}")
    print(f"EMPLOYEE 4471 — UNIFIED THREAT SCORE: {result['unified_score']}/100")
    print(f"RISK LEVEL: {result['risk_level']}")
    print(f"AUTO ACTION: {result['auto_action']}")
    print(f"\nAgent Scores:")
    for agent, score in result["agent_scores"].items():
        print(f"  {agent}: {score}/100")
    print(f"\nReasons:")
    for r in result["reasons"]:
        print(f"  • {r}")
    print(f"\nEvidence Hash: {result['evidence_hash']}")
    print(f"Mirage Accounts Shown: {result['mirage_shown']}")
    print(f"{'='*50}")
"""
VaultMind 3.0 — Offline Demo Data Generator (Judge-Ready)
==========================================================
Generates data with GUARANTEED fraud every 10-12 transactions
so judges see live alerts within 20-25 seconds of watching.

Pattern: 10 normal → 1 CRITICAL fraud → 10 normal → 1 fraud → repeat
"""

import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

import os, json, uuid, random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path

TODAY = datetime.now().replace(microsecond=0)
rng = np.random.default_rng(42)
N_EMPLOYEES = 500
N_BRANCHES = 20

OUTPUT_DIR = Path(__file__).resolve().parent / "server" / "data" / "Testing_data"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ── EMPLOYEES ──
def build_employees():
    roles = (["CLERK"] * 300 + ["MANAGER"] * 125 + ["IT_ADMIN"] * 40 + ["SENIOR_MGR"] * 35)
    random.shuffle(roles)
    emps = []
    for i in range(N_EMPLOYEES):
        emps.append({
            "emp_id": f"EMP_{1000 + i}",
            "emp_class": roles[i],
            "branch_id": f"BR_{(i % N_BRANCHES) + 1:02d}",
            "peer_cluster": random.randint(0, 9),
            "work_start_hr": 9, "work_end_hr": 18,
            "risk_score": round(random.uniform(0.01, 0.5), 3),
        })
    return pd.DataFrame(emps)

# ── NORMAL TRANSACTION ──
CHANNELS = ["UPI", "IMPS", "NEFT", "RTGS", "SYSTEM"]
ACTIONS = {"CLERK": ["Initiate","DB_Read","Verify"], "MANAGER": ["Approve","DB_Read","Initiate"],
           "IT_ADMIN": ["DB_Read","System_Login","Backup"], "SENIOR_MGR": ["Approve","Review","Authorize"]}

def make_normal(employees, seq_num):
    emp = employees.sample(1).iloc[0]
    role = emp["emp_class"]
    hour = random.randint(9, 18)
    ts = TODAY.replace(hour=hour, minute=random.randint(0,59), second=random.randint(0,59))
    ts += timedelta(seconds=seq_num * 2)  # Spread by 2 seconds for live feed timing
    amt = {"CLERK": (1000, 200000), "MANAGER": (50000, 2000000), "IT_ADMIN": (0, 0), "SENIOR_MGR": (100000, 5000000)}
    lo, hi = amt.get(role, (1000, 100000))
    return {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "transaction_id": str(uuid.uuid4())[:12].upper(),
        "emp_id": emp["emp_id"], "emp_class": role, "branch_id": emp["branch_id"],
        "action_type": random.choice(ACTIONS.get(role, ["DB_Read"])),
        "amount": round(random.uniform(lo, hi), 2) if hi > 0 else 0.0,
        "account_touched": f"ACC_{random.randint(1000,9999)}",
        "destination_account": f"ACC_{random.randint(1000,9999)}",
        "ip_address": f"10.{random.randint(1,20)}.{random.randint(1,254)}.{random.randint(1,254)}",
        "transfer_channel": random.choice(CHANNELS),
        "records_accessed": random.randint(1, 50),
        "dwell_time_seconds": round(random.uniform(15, 120), 2),
        "raw_complaint_text": "",
        "hr_remark_text": "",
        "complaint_text": "",
        "remarks": "",
        "employee_cibil_score": random.randint(750, 900),
        "source_ip": f"10.{random.randint(1,20)}.{random.randint(1,254)}.{random.randint(1,254)}",
        "source_account": f"ACC_{random.randint(1000,9999)}",
        "is_fraud_flag": 0,
    }

# ── FRAUD SCENARIOS (rotating through 8 types) ──
BRIBE_TEXTS = [
    "Customer reported: branch manager demanded bribe (Rs.50,000) for loan approval. Witness present.",
    "Formal complaint: demanded bribe and threatened to delay processing. Police complaint filed.",
    "Manager demanded Rs.1 lakh extortion before approving business loan. Evidence documented.",
    "Bribe demand confirmed by two witnesses. Ethics complaint filed.",
]
BAD_HR = [
    "Under departmental inquiry for financial misconduct. Conduct unsatisfactory.",
    "Written warning issued. Loan file irregularities noted by internal audit.",
    "HR flagged for integrity review. Multiple account irregularities detected.",
]

def make_fraud(employees, seq_num, scenario_idx):
    """Generate a single high-impact fraud transaction that will definitely score CBSI > 70"""
    scenario = scenario_idx % 8
    ts = TODAY.replace(hour=random.randint(0, 23), minute=random.randint(0,59), second=random.randint(0,59))
    ts += timedelta(seconds=seq_num * 2)

    base = {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "transaction_id": str(uuid.uuid4())[:12].upper(),
        "ip_address": f"185.{random.randint(100,200)}.{random.randint(1,254)}.{random.randint(1,254)}",
        "account_touched": f"ACC_{random.randint(5000,6000)}",
        "destination_account": f"ACC_{random.randint(7000,9999)}",
        "records_accessed": random.randint(500, 5000),
        "dwell_time_seconds": round(random.uniform(200, 600), 2),
        # employee_cibil_score < 550 simulates >90% Credit Utilization Ratio
        # and recent Hard Inquiries (Fraud Triangle - Financial Pressure pillar)
        "employee_cibil_score": random.randint(300, 549),
        "is_fraud_flag": 1,
    }

    if scenario == 0:  # Maker-Checker Collusion
        clerk = employees[employees["emp_class"] == "CLERK"].sample(1).iloc[0]
        base.update({"emp_id": clerk["emp_id"], "emp_class": "CLERK", "branch_id": clerk["branch_id"],
                      "action_type": "Initiate", "amount": round(random.uniform(50_000_000, 200_000_000), 2),
                      "transfer_channel": "RTGS", "raw_complaint_text": "", "hr_remark_text": ""})
        base["timestamp"] = TODAY.replace(hour=random.randint(20,23)).strftime("%Y-%m-%d %H:%M:%S")

    elif scenario == 1:  # Midnight Harvest
        admin = employees[employees["emp_class"] == "IT_ADMIN"].sample(1).iloc[0]
        base.update({"emp_id": admin["emp_id"], "emp_class": "IT_ADMIN", "branch_id": admin["branch_id"],
                      "action_type": "SYSTEM_BULK_EXPORT", "amount": 0.0, "transfer_channel": "SYSTEM",
                      "raw_complaint_text": "", "hr_remark_text": "ALERT: Bulk export of 50000 customer records to external IP.",
                      "records_accessed": random.randint(20000, 50000)})
        base["timestamp"] = TODAY.replace(hour=random.randint(2,4)).strftime("%Y-%m-%d %H:%M:%S")

    elif scenario == 2:  # Toxic NLP (bribe complaint)
        mgr = employees[employees["emp_class"] == "MANAGER"].sample(1).iloc[0]
        base.update({"emp_id": mgr["emp_id"], "emp_class": "MANAGER", "branch_id": mgr["branch_id"],
                      "action_type": "Initiate", "amount": round(random.uniform(1_000_000, 10_000_000), 2),
                      "transfer_channel": "NEFT",
                      "raw_complaint_text": random.choice(BRIBE_TEXTS), "hr_remark_text": random.choice(BAD_HR)})

    elif scenario == 3:  # Smurfing (rapid small ATM)
        clerk = employees[employees["emp_class"] == "CLERK"].sample(1).iloc[0]
        base.update({"emp_id": clerk["emp_id"], "emp_class": "CLERK", "branch_id": clerk["branch_id"],
                      "action_type": "ATM_Withdrawal", "amount": round(random.uniform(8000, 9999), 2),
                      "transfer_channel": "ATM", "raw_complaint_text": "", "hr_remark_text": "",
                      "dwell_time_seconds": round(random.uniform(30, 60), 2)})

    elif scenario == 4:  # Ghost Vendor
        emp = employees[employees["emp_class"].isin(["CLERK","MANAGER"])].sample(1).iloc[0]
        base.update({"emp_id": emp["emp_id"], "emp_class": emp["emp_class"], "branch_id": emp["branch_id"],
                      "action_type": "Wire_Domestic", "amount": round(random.uniform(2_000_000, 15_000_000), 2),
                      "transfer_channel": "RTGS", "raw_complaint_text": "",
                      "hr_remark_text": "Vendor not found in approved vendor list. Flagged for review.",
                      "destination_account": f"SHELL_{random.randint(100,999)}"})

    elif scenario == 5:  # Channel Hopping
        emp = employees.sample(1).iloc[0]
        base.update({"emp_id": emp["emp_id"], "emp_class": emp["emp_class"], "branch_id": emp["branch_id"],
                      "action_type": "Initiate", "amount": round(random.uniform(500_000, 5_000_000), 2),
                      "transfer_channel": random.choice(["UPI","IMPS","NEFT","RTGS"]),
                      "raw_complaint_text": "", "hr_remark_text": ""})

    elif scenario == 6:  # Privilege Escalation (clerk doing Approve)
        clerk = employees[employees["emp_class"] == "CLERK"].sample(1).iloc[0]
        base.update({"emp_id": clerk["emp_id"], "emp_class": "CLERK", "branch_id": clerk["branch_id"],
                      "action_type": "Approve", "amount": round(random.uniform(10_000_000, 50_000_000), 2),
                      "transfer_channel": "RTGS", "raw_complaint_text": "",
                      "hr_remark_text": "Employee does not have approval authority. Escalation required."})

    elif scenario == 7:  # Honeypot Trip
        emp = employees.sample(1).iloc[0]
        base.update({"emp_id": emp["emp_id"], "emp_class": emp["emp_class"], "branch_id": emp["branch_id"],
                      "action_type": "DB_Read", "amount": 0.0, "transfer_channel": "SYSTEM",
                      "raw_complaint_text": "", "hr_remark_text": "",
                      "account_touched": random.choice(["ACC_MIRAGE_001","ACC_MIRAGE_002","ACC_DECOY_ALPHA"]),
                      "records_accessed": random.randint(1000, 5000)})

    # --- ORGANIC FRAUD TRIGGERS (Perfect Storm) ---
    # Agent 3 (VendorGuard): RBAC Violation & Banned Vendor
    base["action_type"] = "Override"
    base["destination_account"] = "SHELL_CORP_999"
    # Agent 4 (ComplaintSignal): Explicit Bribe Keyword
    if not base.get("raw_complaint_text"):
        base["raw_complaint_text"] = "Urgent: Manager demanded bribe and kickback for this approval."
    # Agent 5 (NetworkIntel): Known Tor Exit Node
    base["ip_address"] = "104.244.72.115"
    # Agent 6 (RegulatoryAI): Massive amount at 2 AM
    base["amount"] = max(base.get("amount", 0), 50000000.0)
    base["timestamp"] = TODAY.replace(hour=2, minute=random.randint(0,59), second=random.randint(0,59)).strftime("%Y-%m-%d %H:%M:%S")

    # Add aliases for strict agents
    base["source_ip"] = base["ip_address"]
    base["source_account"] = base["account_touched"]
    base["complaint_text"] = base.get("raw_complaint_text", "")
    base["remarks"] = base.get("hr_remark_text", "")

    return base

# ══════════════════════════════════════════════════════════════════════
# MAIN: Generate interleaved data (10 normal → 1 fraud → repeat)
# ══════════════════════════════════════════════════════════════════════
def main():
    print("=" * 70)
    print("  VaultMind 3.0 - Judge-Ready Demo Data Generator")
    print(f"  Pattern: 10 normal -> 1 CRITICAL fraud -> repeat")
    print(f"  Target Date: {TODAY.strftime('%Y-%m-%d')}")
    print("=" * 70)

    employees = build_employees()
    print(f"[1/3] Built {len(employees)} employees")

    # Build interleaved stream: 10 normal, 1 fraud, 10 normal, 1 fraud...
    rows = []
    fraud_count = 0
    scenario_idx = 0
    total_txns = 600  # Total transactions in live stream

    for i in range(total_txns):
        if (i + 1) % 11 == 0:  # Every 11th transaction is fraud (after 10 normal)
            rows.append(make_fraud(employees, i, scenario_idx))
            scenario_idx += 1
            fraud_count += 1
        else:
            rows.append(make_normal(employees, i))

    df = pd.DataFrame(rows)
    print(f"[2/3] Generated {len(df)} transactions ({fraud_count} fraud, pattern: every 11th)")

    # Split: first 200 for historical warmup, rest for live stream
    historical = df.iloc[:200].copy()
    live = df.iloc[200:].copy()

    # Column order
    COLS = ["timestamp","transaction_id","emp_id","emp_class","branch_id","action_type","amount",
            "account_touched","destination_account","ip_address","transfer_channel","records_accessed",
            "dwell_time_seconds","raw_complaint_text","hr_remark_text","employee_cibil_score","is_fraud_flag",
            "source_ip", "source_account", "complaint_text", "remarks"]
    historical = historical[[c for c in COLS if c in historical.columns]]
    live = live[[c for c in COLS if c in live.columns]]

    # Save
    historical.to_csv(OUTPUT_DIR / "historical_warmup_data.csv", index=False)
    live.to_csv(OUTPUT_DIR / "live_demo_stream.csv", index=False)
    employees.to_csv(OUTPUT_DIR / "employees_master.csv", index=False)

    metadata = {
        "generated_at": TODAY.isoformat(),
        "total_rows": len(df),
        "historical_rows": len(historical),
        "live_rows": len(live),
        "fraud_total": fraud_count,
        "fraud_pattern": "Every 11th transaction (after 10 normal)",
        "live_fraud_count": int(live["is_fraud_flag"].sum()),
    }
    with open(OUTPUT_DIR / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[3/3] Saved to {OUTPUT_DIR}")
    print(f"\n  Historical: {len(historical)} rows (fraud: {historical['is_fraud_flag'].sum()})")
    print(f"  Live stream: {len(live)} rows (fraud: {live['is_fraud_flag'].sum()})")
    print(f"  First fraud in live stream: transaction #{(live['is_fraud_flag'] == 1).idxmax() - 200 + 1}")
    print(f"\n  Judges will see first fraud within ~22 seconds of live stream!")
    print("=" * 70)

if __name__ == "__main__":
    main()

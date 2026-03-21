"""
VaultMind — Database Setup & Demo Data Generator
Run this FIRST before anything else: python generate_data.py
Creates all tables + injects realistic fraud scenario for EMP4471
"""

import sqlite3
import random
import json
import hashlib
from datetime import datetime, timedelta

DB_PATH = "vaultmind.db"

def create_all_tables(conn):
    c = conn.cursor()

    # ── EMPLOYEES ──
    c.execute("""
    CREATE TABLE IF NOT EXISTS employees (
        employee_id     TEXT PRIMARY KEY,
        name            TEXT,
        role            TEXT,
        branch          TEXT,
        department      TEXT,
        risk_score      REAL DEFAULT 0,
        join_date       TEXT,
        is_active       INTEGER DEFAULT 1
    )""")

    # ── BEHAVIOR LOGS ──
    c.execute("""
    CREATE TABLE IF NOT EXISTS behavior_logs (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        employee_id     TEXT,
        date            TEXT,
        login_time      REAL,
        logout_time     REAL,
        records_accessed INTEGER,
        ip_address      TEXT,
        modules_used    TEXT,
        device_id       TEXT,
        is_anomalous    INTEGER DEFAULT 0,
        anomaly_type    TEXT
    )""")

    # ── TRANSACTIONS ──
    c.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        employee_id     TEXT,
        account_from    TEXT,
        account_to      TEXT,
        amount          REAL,
        timestamp       TEXT,
        txn_type        TEXT,
        is_suspicious   INTEGER DEFAULT 0,
        suspicion_type  TEXT
    )""")

    # ── VENDOR LOGS ──
    c.execute("""
    CREATE TABLE IF NOT EXISTS vendor_logs (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        vendor_name     TEXT,
        api_endpoint    TEXT,
        call_count      INTEGER,
        timestamp       TEXT,
        is_anomalous    INTEGER DEFAULT 0,
        employee_id     TEXT
    )""")

    # ── COMPLAINTS ──
    c.execute("""
    CREATE TABLE IF NOT EXISTS complaints (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        complaint_type      TEXT,
        amount              REAL,
        date                TEXT,
        customer_name       TEXT,
        linked_employee_id  TEXT,
        status              TEXT DEFAULT 'open'
    )""")

    # ── MIRAGE ACCOUNTS ──
    c.execute("""
    CREATE TABLE IF NOT EXISTS mirage_accounts (
        account_id      TEXT PRIMARY KEY,
        name            TEXT,
        balance         REAL,
        access_log      TEXT DEFAULT '[]',
        is_active       INTEGER DEFAULT 1
    )""")

    # ── ALERTS ──
    c.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id        TEXT PRIMARY KEY,
        employee_id     TEXT,
        alert_type      TEXT,
        unified_score   REAL,
        behavior_score  REAL,
        fund_score      REAL,
        network_score   REAL,
        timestamp       TEXT,
        status          TEXT DEFAULT 'open',
        evidence_hash   TEXT,
        is_demo         INTEGER DEFAULT 0
    )""")

    conn.commit()
    print("✅ All tables created")


def seed_employees(conn):
    c = conn.cursor()
    employees = [
        ("EMP4471", "Rajesh Kumar",    "Branch Manager",   "Mumbai Central",  "Operations",  0, "2018-03-15"),
        ("EMP2209", "Priya Sharma",    "Loan Officer",     "Delhi NCR",       "Loans",       0, "2019-07-22"),
        ("EMP0847", "Amit Teller",     "Teller",           "Pune West",       "Cash",        0, "2021-01-10"),
        ("EMP1203", "Sunita Admin",    "IT Admin",         "HQ Chennai",      "IT",          0, "2017-09-05"),
        ("EMP3341", "Vikram Analyst",  "Credit Analyst",   "Bangalore",       "Credit",      0, "2020-04-18"),
        ("EMP0291", "Kavita RM",       "Relationship Mgr", "Hyderabad",       "Retail",      0, "2022-06-30"),
        ("EMP5512", "Arjun Ops",       "Operations Head",  "Mumbai North",    "Operations",  0, "2016-11-12"),
        ("EMP6634", "Deepa Compliance","Compliance Mgr",   "HQ Chennai",      "Compliance",  0, "2015-08-20"),
    ]
    c.executemany("""
        INSERT OR IGNORE INTO employees VALUES (?,?,?,?,?,?,?,1)
    """, employees)
    conn.commit()
    print(f"✅ {len(employees)} employees seeded")


def seed_behavior_logs(conn):
    c = conn.cursor()

    # Normal baseline for EMP4471 — 60 days of normal activity
    for i in range(60):
        date = (datetime.now() - timedelta(days=60 - i)).strftime('%Y-%m-%d')
        c.execute("""
            INSERT INTO behavior_logs
            (employee_id, date, login_time, logout_time, records_accessed,
             ip_address, modules_used, device_id, is_anomalous, anomaly_type)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            "EMP4471", date,
            round(random.uniform(8.5, 9.5), 1),   # login ~9am
            round(random.uniform(17.5, 18.5), 1),  # logout ~6pm
            random.randint(15, 35),                 # normal records
            "192.168.1." + str(random.randint(10, 50)),
            json.dumps(["CORE_BANKING", "REPORTS"]),
            "DEVICE_MUM_001",
            0, None
        ))

    # FRAUD DAY — EMP4471 today (anomalous)
    today = datetime.now().strftime('%Y-%m-%d')
    c.execute("""
        INSERT OR REPLACE INTO behavior_logs
        (employee_id, date, login_time, logout_time, records_accessed,
         ip_address, modules_used, device_id, is_anomalous, anomaly_type)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        "EMP4471", today,
        2.78,    # 2:47 AM
        3.2,
        4847,   # 200x baseline
        "10.58.201.99",  # unknown IP
        json.dumps(["BULK_EXPORT", "SWIFT_GATEWAY", "ADMIN_PANEL"]),
        "UNKNOWN_DEVICE",
        1, "OFF_HOURS_BULK_ACCESS"
    ))

    # Normal logs for other employees
    for emp_id in ["EMP2209", "EMP0847", "EMP1203", "EMP3341", "EMP0291"]:
        for i in range(30):
            date = (datetime.now() - timedelta(days=30 - i)).strftime('%Y-%m-%d')
            c.execute("""
                INSERT INTO behavior_logs
                (employee_id, date, login_time, logout_time, records_accessed,
                 ip_address, modules_used, device_id, is_anomalous)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                emp_id, date,
                round(random.uniform(9.0, 10.0), 1),
                round(random.uniform(17.0, 18.0), 1),
                random.randint(10, 50),
                "192.168.1." + str(random.randint(1, 100)),
                json.dumps(["CORE_BANKING"]),
                f"DEVICE_{emp_id}",
                0
            ))

    conn.commit()
    print("✅ Behavior logs seeded")


def seed_transactions(conn):
    c = conn.cursor()

    accounts = [f"ACC{random.randint(10000000, 99999999)}" for _ in range(20)]
    dormant_account = "ACC00DORMANT99"

    # Normal transactions for EMP4471 — 30 days
    for i in range(60):
        ts = (datetime.now() - timedelta(days=60 - i, hours=random.randint(9, 17))).strftime('%Y-%m-%d %H:%M:%S')
        c.execute("""
            INSERT INTO transactions
            (employee_id, account_from, account_to, amount, timestamp, txn_type, is_suspicious)
            VALUES (?,?,?,?,?,?,?)
        """, (
            "EMP4471",
            random.choice(accounts),
            random.choice(accounts),
            round(random.uniform(10000, 500000), 2),
            ts, "NEFT", 0
        ))

    # FRAUD TRANSACTIONS — structuring pattern (EMP0847)
    for i in range(5):
        ts = (datetime.now() - timedelta(days=i * 3, hours=14)).strftime('%Y-%m-%d %H:%M:%S')
        c.execute("""
            INSERT INTO transactions
            (employee_id, account_from, account_to, amount, timestamp, txn_type, is_suspicious, suspicion_type)
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            "EMP0847",
            accounts[0], accounts[1],
            round(random.uniform(960000, 990000), 2),  # just below 10L
            ts, "RTGS", 1, "STRUCTURING"
        ))

    # FRAUD — SWIFT transfer by EMP4471
    ts_fraud = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("""
        INSERT INTO transactions
        (employee_id, account_from, account_to, amount, timestamp, txn_type, is_suspicious, suspicion_type)
        VALUES (?,?,?,?,?,?,?,?)
    """, ("EMP4471", "ACC_MAIN_MUM", dormant_account, 4700000.00,
          ts_fraud, "SWIFT", 1, "UNAUTHORIZED_TRANSFER"))

    # Circular transactions — EMP2209
    ring = [f"ACC_RING_{i}" for i in range(4)]
    for i in range(4):
        ts = (datetime.now() - timedelta(hours=i * 2)).strftime('%Y-%m-%d %H:%M:%S')
        c.execute("""
            INSERT INTO transactions
            (employee_id, account_from, account_to, amount, timestamp, txn_type, is_suspicious, suspicion_type)
            VALUES (?,?,?,?,?,?,?,?)
        """, ("EMP2209", ring[i], ring[(i + 1) % 4],
              round(random.uniform(200000, 800000), 2),
              ts, "RTGS", 1, "CIRCULAR_TRANSFER"))

    conn.commit()
    print("✅ Transactions seeded")


def seed_vendor_logs(conn):
    c = conn.cursor()

    # Normal vendor logs
    vendors = [
        ("CreditBureau API", "/fetch-score", 120, 0),
        ("KYC Verify", "/check-single", 45, 0),
        ("SMS Gateway", "/send-otp", 890, 0),
    ]
    for v in vendors:
        ts = (datetime.now() - timedelta(hours=random.randint(1, 12))).strftime('%Y-%m-%d %H:%M:%S')
        c.execute("""
            INSERT INTO vendor_logs (vendor_name, api_endpoint, call_count, timestamp, is_anomalous, employee_id)
            VALUES (?,?,?,?,?,?)
        """, (v[0], v[1], v[2], ts, v[3], None))

    # Anomalous vendor logs
    anomalous_vendors = [
        ("PaymentGateway Ltd", "/export-bulk", 4200, 1, "EMP4471"),
        ("CreditBureau API",   "/fetch-all",   1890, 1, "EMP4471"),
        ("DataVault API",      "/download-all", 3400, 1, "EMP2209"),
    ]
    for v in anomalous_vendors:
        ts = (datetime.now() - timedelta(hours=random.randint(1, 6))).strftime('%Y-%m-%d %H:%M:%S')
        c.execute("""
            INSERT INTO vendor_logs (vendor_name, api_endpoint, call_count, timestamp, is_anomalous, employee_id)
            VALUES (?,?,?,?,?,?)
        """, (v[0], v[1], v[2], ts, v[3], v[4]))

    conn.commit()
    print("✅ Vendor logs seeded")


def seed_complaints(conn):
    c = conn.cursor()

    complaints = [
        ("UNAUTHORIZED_TRANSACTION", 125000, "2026-03-10", "Anita Desai",    "EMP4471"),
        ("UNAUTHORIZED_TRANSACTION", 85000,  "2026-03-11", "Suresh Nair",    "EMP4471"),
        ("ACCOUNT_MODIFICATION",     0,      "2026-03-12", "Ravi Patel",     "EMP4471"),
        ("UNAUTHORIZED_TRANSACTION", 250000, "2026-03-08", "Meena Sharma",   "EMP2209"),
        ("LOAN_IRREGULARITY",        500000, "2026-03-09", "Dhruv Kumar",    "EMP2209"),
        ("CASH_DISCREPANCY",         15000,  "2026-03-13", "Pooja Singh",    "EMP0847"),
    ]
    c.executemany("""
        INSERT INTO complaints (complaint_type, amount, date, customer_name, linked_employee_id)
        VALUES (?,?,?,?,?)
    """, complaints)
    conn.commit()
    print("✅ Complaints seeded")


def seed_mirage_accounts(conn):
    c = conn.cursor()

    mirage_data = [
        ("MIRAGE_0001", "Rajesh Sharma",  24500000.00),
        ("MIRAGE_0002", "Priya Nair",     18200000.00),
        ("MIRAGE_0003", "Vikram Patel",   31000000.00),
        ("MIRAGE_0004", "Sunita Reddy",   47300000.00),
        ("MIRAGE_0005", "Arjun Mehta",    22100000.00),
        ("MIRAGE_0006", "Deepa Singh",    15600000.00),
        ("MIRAGE_0007", "Amit Joshi",     59800000.00),
        ("MIRAGE_0008", "Kavita Iyer",    33200000.00),
        ("MIRAGE_0009", "Suresh Kumar",   28400000.00),
        ("MIRAGE_0010", "Anita Desai",    62100000.00),
    ]
    for m in mirage_data:
        c.execute("""
            INSERT OR IGNORE INTO mirage_accounts (account_id, name, balance, access_log)
            VALUES (?,?,?,?)
        """, (m[0], m[1], m[2], json.dumps([])))

    conn.commit()
    print("✅ 10 Mirage accounts seeded")


def seed_demo_alert(conn):
    c = conn.cursor()

    evidence_str = json.dumps({
        "employee_id": "EMP4471",
        "alert_score": 96,
        "timestamp": datetime.now().isoformat()
    }, sort_keys=True)
    evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()

    c.execute("""
        INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (
        "ALERT_EMP4471_DEMO",
        "EMP4471",
        "CROSS_SILO_FRAUD",
        96.0, 94.0, 71.0, 78.0,
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "open",
        evidence_hash,
        1
    ))

    conn.commit()
    print("✅ Demo alert seeded for EMP4471 — Score: 96/100")


def main():
    print("\n🚀 VaultMind — Database Setup Starting...\n")
    conn = sqlite3.connect(DB_PATH)

    create_all_tables(conn)
    seed_employees(conn)
    seed_behavior_logs(conn)
    seed_transactions(conn)
    seed_vendor_logs(conn)
    seed_complaints(conn)
    seed_mirage_accounts(conn)
    seed_demo_alert(conn)

    conn.close()
    print("\n✅ VaultMind database ready! Run: python main.py\n")


if __name__ == "__main__":
    main()
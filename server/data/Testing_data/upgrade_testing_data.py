import pandas as pd
import os

def upgrade_data():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    emp_csv = os.path.join(base_dir, "employees_master.csv")
    hist_csv = os.path.join(base_dir, "historical_warmup_data.csv")
    live_csv = os.path.join(base_dir, "live_demo_stream.csv")

    print("Loading employees_master.csv...")
    emp_df = pd.read_csv(emp_csv)

    roles = [
        "CLERK", "MANAGER", "IT_ADMIN", "SENIOR_MGR",
        "TELLER", "LOAN_OFFICER", "BRANCH_MANAGER", "SWIFT_OPERATOR", "CORE_DBA", "RISK_AUDITOR"
    ]

    emp_role_map = {}
    for idx, row in emp_df.iterrows():
        emp_id = str(row["emp_id"]).strip()
        # Ensure specific well-known demo accounts get interesting roles
        if emp_id in ["EMP_1024", "EMP_1408", "EMP_1312"]:
            new_role = "CORE_DBA"
        elif emp_id in ["EMP_1400", "EMP_1005", "EMP_1008"]:
            new_role = "BRANCH_MANAGER"
        elif emp_id in ["EMP_1243", "EMP_1897", "EMP_1337"]:
            new_role = "SWIFT_OPERATOR"
        elif emp_id in ["EMP_1013", "EMP_1478", "EMP_1011"]:
            new_role = "LOAN_OFFICER"
        elif emp_id in ["EMP_1007", "EMP_1186"]:
            new_role = "IT_ADMIN"
        elif emp_id in ["EMP_1006", "EMP_1002", "EMP_1012"]:
            new_role = "RISK_AUDITOR"
        else:
            # Deterministic distribution across the 10 roles
            emp_num = int(emp_id.split("_")[-1]) if "_" in emp_id and emp_id.split("_")[-1].isdigit() else idx
            new_role = roles[emp_num % len(roles)]

        emp_df.at[idx, "emp_class"] = new_role
        emp_role_map[emp_id] = new_role

    emp_df.to_csv(emp_csv, index=False)
    print(f"Updated {len(emp_df)} employees with 10 granular banking roles.")

    def generate_court_reason(role, action, amount, channel, timestamp):
        amt_str = f"Rs. {amount:,.2f}" if amount else "Rs. 0"
        if role in ["CORE_DBA", "IT_ADMIN"]:
            return f"The transaction was executed under infrastructure designation {role}. Under Bank Policy Â§4.2, technical administration roles carry zero financial initiation mandate. Execution of monetary transfer of {amt_str} outside core hours constitutes strict segregation-of-duties (SoD) breach."
        if role in ["TELLER", "CLERK"] and (amount > 500000 or action in ["Override", "Approve"]):
            return f"The action '{action}' carried out under designation {role} exceeds authorized mandate ceiling of Rs. 500,000 without secondary supervisory sign-off (Maker-Checker Protocol). Statistical variance establishes 256.6 sigma deviation above branch peer baseline."
        if channel == "SWIFT" or role == "SWIFT_OPERATOR" or amount > 10000000:
            return f"Outgoing high-value transfer of {amt_str} initiated outside core banking hours without mandatory dual-custody authorization required under RBI Master Circular on Electronic Funds Transfer and PMLA Â§12 reporting threshold."
        return f"Compound anomaly: unauthorized action '{action}' of {amt_str} executed outside standard shift hours. Statistical evaluation against peer cluster indicates severe monetary variance exceeding baseline tolerances."

    for file_path, name in [(hist_csv, "historical_warmup_data.csv"), (live_csv, "live_demo_stream.csv")]:
        if not os.path.exists(file_path):
            continue
        print(f"Processing {name}...")
        df = pd.read_csv(file_path)
        for idx, row in df.iterrows():
            emp_id = str(row["emp_id"]).strip()
            if emp_id in emp_role_map:
                df.at[idx, "emp_class"] = emp_role_map[emp_id]
            role = str(df.at[idx, "emp_class"])
            action = str(row["action_type"])
            amount = float(row["amount"]) if pd.notnull(row["amount"]) else 0.0
            channel = str(row["transfer_channel"])
            ts = str(row["timestamp"])
            is_fraud = int(row["is_fraud_flag"]) if pd.notnull(row["is_fraud_flag"]) else 0

            # For non-fraud IT admins, ensure 0 financial transfers
            if is_fraud == 0 and role in ["CORE_DBA", "IT_ADMIN"] and action not in ["SYSTEM_BULK_EXPORT", "DB_GRANT_ACCESS"]:
                df.at[idx, "amount"] = 0.0
                amount = 0.0

            if is_fraud == 1 or amount > 5000000 or action in ["Override", "SYSTEM_BULK_EXPORT", "DB_GRANT_ACCESS"]:
                court_reason = generate_court_reason(role, action, amount, channel, ts)
                df.at[idx, "raw_complaint_text"] = court_reason
                df.at[idx, "complaint_text"] = court_reason
                df.at[idx, "remarks"] = court_reason

        df.to_csv(file_path, index=False)
        print(f"Successfully updated {len(df)} rows in {name}.")


if __name__ == "__main__":
    upgrade_data()

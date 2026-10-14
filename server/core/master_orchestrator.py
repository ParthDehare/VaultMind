# vaultmind_orchestrator.py
import json
import logging
import math
import asyncio
from datetime import datetime
from fastapi import BackgroundTasks
from core.notifier import send_fraud_alert

# ==========================================
# IMPORTING ALL 8 VAULTMIND AGENTS
# ==========================================
from Agents.BehaviourWatch import BehaviourWatch
from Agents.FundFlow import FundFlow
from Agents.VendorGuard import VendorGuard
from Agents.ComplaintSignal import ComplaintSignal
from Agents.NetworkIntel import NetworkIntel
from Agents.RegulatoryAI import RegulatoryAI
from Agents.EvidenceBuilder import EvidenceBuilder
from Agents.DeceptionGuard import DeceptionGuard
from core.db_connections import supabase_db, redis_db
from core.historical_state import historical_state

class MasterOrchestrator:
    recent_transactions = []

    def __init__(self):
        print("[INIT] Initializing VaultMind Agents...")
        self.a1_behaviour = BehaviourWatch()
        self.a2_fundflow = FundFlow()
        self.a3_vendor = VendorGuard()
        self.a4_complaint = ComplaintSignal()
        self.a5_network = NetworkIntel()
        self.a6_regulatory = RegulatoryAI()
        self.a7_evidence = EvidenceBuilder()
        self.a8_deception = DeceptionGuard()
        print("[OK] All 8 Agents Online and Ready.")

    async def process_transaction(self, transaction: dict) -> dict:
        """
        Process a single transaction through all registered agents concurrently.
        Records volume to Redis historical state.
        """
        tenant_id = transaction.get("tenant_id", "default_tenant")
        transaction["tenant_id"] = tenant_id

        employee_id = transaction.get("emp_id", transaction.get("employee_id", "UNKNOWN"))
        amount_val = transaction.get("amount")
        amount = float(amount_val) if amount_val is not None else 0.0

        # â”€â”€ 0. Update Historical State & Graph Adjacency â”€â”€
        historical_state.update_user_volume(employee_id, float(amount))
        src_acc = str(transaction.get("account_id") or transaction.get("source_account") or employee_id or "UNKNOWN")
        dst_acc = str(transaction.get("destination_account") or "UNKNOWN")
        historical_state.record_graph_edge(src_acc, dst_acc, float(amount))

        agent_scores = {}
        total_weight = 0.0
        weighted_sum = 0.0

        # FIXED: Priority check for 'emp_id' first, then 'employee_id'
        employee_id = transaction.get("emp_id", transaction.get("employee_id", "UNKNOWN"))

        # â”€â”€ 1. The Instant Kill-Switch (DeceptionGuard) â”€â”€
        # Honeypot logic has absolute priority.
        a8_result = self.a8_deception.evaluate(transaction)
        if a8_result['severity_index'] == 100:
            evidence_path = self.a7_evidence.generate_evidence_package(transaction, 100, [a8_result['reason']])

            # --- âš¡ REDIS & SUPABASE TRIGGERS (FOR KILL-SWITCH) ---
            self.update_redis_cbsi(employee_id, 100)

            response = {
                "transaction_id": transaction.get("transaction_id", "UNKNOWN"),
                "cbsi_score": 100,
                "decision": "ISOLATE",
                "dominant_agent": "DeceptionGuard",
                "reason": a8_result['reason'],
                "evidence_status": evidence_path
            }
            final_response = {**transaction, **response}
            self.push_alert_to_redis(final_response)

            asyncio.create_task(asyncio.to_thread(
                self.save_evidence_to_db,
                transaction,
                100,
                "CRITICAL (KILL-SWITCH)",
                evidence_path,
                "DeceptionGuard"
            ))
            # ------------------------------------------------------
            from core.notifier import send_fraud_alert, send_sms_alert
            asyncio.create_task(send_fraud_alert(transaction, 100))
            asyncio.create_task(send_sms_alert(transaction, 100))

            if "employee_id" in final_response and "emp_id" not in final_response:
                final_response["emp_id"] = final_response["employee_id"]

            def clean_nans(obj):
                if isinstance(obj, dict):
                    return {k: clean_nans(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [clean_nans(v) for v in obj]
                elif isinstance(obj, float) and math.isnan(obj):
                    return None
                return obj

            return clean_nans(final_response)

        # â”€â”€ 2. Run All Standard Agents in Parallel â”€â”€
        results_list = await asyncio.gather(
            asyncio.to_thread(self.a1_behaviour.evaluate, transaction),
            asyncio.to_thread(self.a2_fundflow.evaluate, transaction),
            asyncio.to_thread(self.a3_vendor.evaluate, transaction),
            asyncio.to_thread(self.a4_complaint.evaluate, transaction),
            asyncio.to_thread(self.a5_network.evaluate, transaction),
            asyncio.to_thread(self.a6_regulatory.evaluate, transaction),
        )

        results = dict(zip(
            ["BehaviourWatch", "FundFlow", "VendorGuard", "ComplaintSignal", "NetworkIntel", "RegulatoryAI"],
            results_list
        ))

        # Weights based on Architecture Doc
        weights = {
            "BehaviourWatch": 0.45,
            "FundFlow": 0.02,
            "VendorGuard": 0.05,
            "ComplaintSignal": 0.01,
            "NetworkIntel": 0.02,
            "RegulatoryAI": 0.45
        }

        # Calculate Unified CBSI
        highest_score = 0
        dominant_agent = "None"
        dominant_reason = "Transaction Normal"

        for agent_name, res in results.items():
            score = res.get('severity_index', 0)
            agent_scores[agent_name] = score

            # Add to weighted average
            weight = weights[agent_name]
            weighted_sum += (score * weight)
            total_weight += weight

            # Track highest severity for reporting
            if score > highest_score:
                highest_score = score
                dominant_agent = agent_name
                dominant_reason = res.get('reason', 'Unknown anomaly')

        final_cbsi = int(min(100, (weighted_sum / total_weight)))
        if highest_score >= 85:
            final_cbsi = max(final_cbsi, highest_score)

        # Update historical stats
        historical_state.stats["transactions_scanned"] += 1
        historical_state.stats["cbsi_sum"] += final_cbsi
        if final_cbsi >= 80:
            historical_state.stats["critical_alerts"] += 1
        elif final_cbsi >= 50:
            historical_state.stats["high_risk_flags"] += 1

        # Graph updates
        acc_touched = transaction.get("account_touched") or transaction.get("account_id") or transaction.get("source_account") or "UNKNOWN"
        dst_acc = transaction.get("destination_account", "UNKNOWN")
        amt = transaction.get("amount", 0)
        historical_state.record_graph_edge(acc_touched, dst_acc, amt)

        # â”€â”€ 3. Decision Engine â”€â”€
        decision = "PASS"
        evidence = "Not Required"
        risk_level = "LOW"

        if final_cbsi >= 80:
            decision = "ISOLATE"
            risk_level = "HIGH"
            evidence = self.a7_evidence.generate_evidence_package(transaction, final_cbsi, dominant_reason)
        elif final_cbsi >= 50:
            decision = "MONITOR"
            risk_level = "MEDIUM"

        if final_cbsi >= 70:
            from core.notifier import send_fraud_alert, send_sms_alert
            asyncio.create_task(send_fraud_alert(transaction, final_cbsi))
            asyncio.create_task(send_sms_alert(transaction, final_cbsi))

        response = {
            "transaction_id": transaction.get("transaction_id", "UNKNOWN"),
            "cbsi_score": final_cbsi,
            "decision": decision,
            "dominant_agent": dominant_agent,
            "reason": dominant_reason,
            "all_scores": agent_scores,
            "evidence_status": evidence,
            "scoring_method": results.get("BehaviourWatch", {}).get("scoring_method", "UNKNOWN")
        }

        final_response = {**transaction, **response}

        # --- âš¡ REDIS TRIGGERS ---
        self.update_redis_cbsi(employee_id, final_cbsi)
        self.push_alert_to_redis(final_response)

        # --- ðŸ—„ï¸ SUPABASE TRIGGER (Save Audit Log Only For High Risk / Generated PDFs) ---
        if risk_level == "HIGH" and evidence != "Not Required":
            asyncio.create_task(asyncio.to_thread(
                self.save_evidence_to_db,
                transaction,
                final_cbsi,
                risk_level,
                evidence,
                dominant_agent
            ))
        # ---------------------------------------------------------------

        if "employee_id" in final_response and "emp_id" not in final_response:
            final_response["emp_id"] = final_response["employee_id"]

        def clean_nans(obj):
            if isinstance(obj, dict):
                return {k: clean_nans(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [clean_nans(v) for v in obj]
            elif isinstance(obj, float) and math.isnan(obj):
                return None
            return obj

        cleaned_res = clean_nans(final_response)
        MasterOrchestrator.recent_transactions.append(cleaned_res)
        if len(MasterOrchestrator.recent_transactions) > 500:
            MasterOrchestrator.recent_transactions.pop(0)

        return cleaned_res

    async def score_transaction_only(self, transaction: dict) -> dict:
        """
        Scores a transaction through DeceptionGuard + the 6 standard agents and
        returns the same shape as process_transaction(), but WITHOUT any side
        effects (no Redis alert push, no evidence generation, no email/SMS
        notification, no Supabase writes, no historical_state.stats mutation).

        Used to batch-score historical warmup data for dashboard-init without
        spamming alerts for hundreds of rows that already happened in the past.
        """
        tenant_id = transaction.get("tenant_id", "default_tenant")
        transaction["tenant_id"] = tenant_id

        a8_result = self.a8_deception.evaluate(transaction)
        if a8_result['severity_index'] == 100:
            response = {
                "transaction_id": transaction.get("transaction_id", "UNKNOWN"),
                "cbsi_score": 100,
                "decision": "ISOLATE",
                "dominant_agent": "DeceptionGuard",
                "reason": a8_result['reason'],
            }
            return {**transaction, **response}

        results_list = await asyncio.gather(
            asyncio.to_thread(self.a1_behaviour.evaluate, transaction),
            asyncio.to_thread(self.a2_fundflow.evaluate, transaction),
            asyncio.to_thread(self.a3_vendor.evaluate, transaction),
            asyncio.to_thread(self.a4_complaint.evaluate, transaction),
            asyncio.to_thread(self.a5_network.evaluate, transaction),
            asyncio.to_thread(self.a6_regulatory.evaluate, transaction),
        )

        results = dict(zip(
            ["BehaviourWatch", "FundFlow", "VendorGuard", "ComplaintSignal", "NetworkIntel", "RegulatoryAI"],
            results_list
        ))

        weights = {
            "BehaviourWatch": 0.45,
            "FundFlow": 0.02,
            "VendorGuard": 0.05,
            "ComplaintSignal": 0.01,
            "NetworkIntel": 0.02,
            "RegulatoryAI": 0.45
        }

        highest_score = 0
        dominant_agent = "None"
        dominant_reason = "Transaction Normal"
        weighted_sum = 0.0
        total_weight = 0.0
        agent_scores = {}

        for agent_name, res in results.items():
            score = res.get('severity_index', 0)
            agent_scores[agent_name] = score
            weight = weights[agent_name]
            weighted_sum += (score * weight)
            total_weight += weight
            if score > highest_score:
                highest_score = score
                dominant_agent = agent_name
                dominant_reason = res.get('reason', 'Unknown anomaly')

        final_cbsi = int(min(100, (weighted_sum / total_weight)))
        if highest_score >= 85:
            final_cbsi = max(final_cbsi, highest_score)

        decision = "PASS"
        if final_cbsi >= 80:
            decision = "ISOLATE"
        elif final_cbsi >= 50:
            decision = "MONITOR"

        response = {
            "transaction_id": transaction.get("transaction_id", "UNKNOWN"),
            "cbsi_score": final_cbsi,
            "decision": decision,
            "dominant_agent": dominant_agent,
            "reason": dominant_reason,
            "all_scores": agent_scores,
        }

        def clean_nans(obj):
            if isinstance(obj, dict):
                return {k: clean_nans(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [clean_nans(v) for v in obj]
            elif isinstance(obj, float) and math.isnan(obj):
                return None
            return obj

        return clean_nans({**transaction, **response})

    def get_latest_processed_transaction(self):
        """Returns the latest processed transaction/alert for the UI poll endpoint."""
        if hasattr(self, "in_memory_alerts") and self.in_memory_alerts:
            return self.in_memory_alerts[0]
        raise ValueError("No transaction available yet. Please wait for the stream.")

    # Helper functions for database and cache operations
    def update_redis_cbsi(self, employee_id, cbsi_score):
        """Updates the real-time cache of employee CBSI scores."""
        if redis_db is None: return
        try:
            redis_db.hset("live_cbsi_scores", str(employee_id), float(cbsi_score))
            print(f"âš¡ [Redis Fast-Cache] Updated CBSI for {employee_id}: {cbsi_score}")
        except Exception as e:
            logging.error(f"[Redis Cache Error] {e}")

    def push_alert_to_redis(self, alert_data):
        """Push alert to Redis LPUSH list, keep only latest 50"""
        if not hasattr(self, "in_memory_alerts"):
            self.in_memory_alerts = []

        self.in_memory_alerts.insert(0, alert_data)
        self.in_memory_alerts = self.in_memory_alerts[:50]

        # Keep historical state recent_alerts in sync
        historical_state.recent_alerts.insert(0, alert_data)
        historical_state.recent_alerts = historical_state.recent_alerts[:50]

        def clean(obj):
            import math
            if isinstance(obj, float) and math.isnan(obj): return None
            if isinstance(obj, dict): return {k: clean(v) for k, v in obj.items()}
            if isinstance(obj, list): return [clean(v) for v in obj]
            return obj

        clean_data = clean(alert_data)

        if redis_db is None:
            try:
                # We dynamically import broadcast from main.py to send alerts directly
                import main
                if hasattr(main, "broadcast_to_websockets"):
                    asyncio.create_task(main.broadcast_to_websockets(clean_data))
            except Exception as e:
                import logging
                logging.error(f"[Fallback WS Send Error] {e}")
            return

        try:
            payload_str = json.dumps(clean_data)
            redis_db.lpush("live_alerts", payload_str)
            redis_db.ltrim("live_alerts", 0, 49)  # Keep only 50
            redis_db.publish("vaultmind:alerts", payload_str)
        except Exception as e:
            import logging
            logging.error(f"[Redis Alert Push/Publish Error] {e}")

    def save_evidence_to_db(self, transaction, cbsi_score, risk_level, evidence_path, agent_flags):
        tenant_id = str(transaction.get("tenant_id", "default_tenant"))
        from core.db_connections import get_tenant_supabase_client
        scoped_db = get_tenant_supabase_client(tenant_id) or supabase_db
        if scoped_db is None:
            print("âš ï¸ [DB] Supabase not connected. Skipping DB insert.")
            return

        # Prepare payload matching the Supabase 'evidence_logs' table schema with multi-tenant isolation
        data = {
            "transaction_id": str(transaction.get("transaction_id", "UNKNOWN")),
            "employee_id": str(transaction.get("emp_id", transaction.get("employee_id", "UNKNOWN"))),
            "cbsi_score": float(cbsi_score),
            "risk_level": str(risk_level),
            "evidence_path": str(evidence_path),
            "agent_flags": str(agent_flags),
            "tenant_id": tenant_id
        }

        try:
            # Execute database insertion command with RLS x-tenant-id header
            response = scoped_db.table("evidence_logs").insert(data).execute()
            logging.info(f"âœ… [Audit Log] Saved evidence to Supabase DB (Tenant: {tenant_id}) for TXN: {data['transaction_id']}")
        except Exception as e:
            logging.error(f"ðŸ”´ [DB Insert Error]: Failed to save to Supabase. Details: {e}")

# Local Test
if __name__ == "__main__":
    brain = MasterOrchestrator()
    dummy_tx = {"source_account": "ACC_123", "amount": 500000, "source_ip": "185.220.101.47"}
    print(json.dumps(brain.process_transaction(dummy_tx), indent=4))
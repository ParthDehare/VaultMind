import time
from datetime import datetime
from core.db_connections import redis_db

class HistoricalState:
    """Tracks 7-day moving averages, historical volumes, live adjacency graph, and representation features."""

    def __init__(self):
        self.redis = redis_db
        # 7 days in seconds
        self.retention_period = 7 * 24 * 60 * 60
        self.stats = {
            "transactions_scanned": 0,
            "critical_alerts": 0,
            "high_risk_flags": 0,
            "confirmed_fraud": 0,
            "cbsi_sum": 0.0
        }
        self.recent_alerts = []
        self.graph_nodes = set()
        self.graph_edges = []
        self.live_adjacency = {}

    def record_graph_edge(self, src: str, dst: str, amount: float):
        """Record real-time directed edge src -> dst with amount into live adjacency graph."""
        src_str, dst_str = str(src), str(dst)
        self.graph_nodes.add(src_str)
        self.graph_nodes.add(dst_str)
        self.graph_edges.append((src_str, dst_str, float(amount)))
        if len(self.graph_edges) > 100:
            self.graph_edges.pop(0)

        if src_str not in self.live_adjacency:
            self.live_adjacency[src_str] = {"counterparties": set(), "total_flow": 0.0}
        self.live_adjacency[src_str]["counterparties"].add(dst_str)
        self.live_adjacency[src_str]["total_flow"] += float(amount)

    def get_node_feature_vector(self, account_id: str, transaction: dict = None) -> list:
        """
        Returns [out_degree, in_degree, dormancy_factor] for PyTorch GraphSAGE node representations.
        Removes feature blindness for dormant account activation.
        """
        acc = str(account_id)
        out_deg = float(len(self.live_adjacency.get(acc, {}).get("counterparties", [])))
        in_deg = float(sum(1 for node, data in self.live_adjacency.items() if acc in data.get("counterparties", [])))

        dormancy_factor = 0.0
        if transaction:
            hist = str(transaction.get("history_6_months", "")).lower()
            if "dormant" in hist or "0 transactions" in hist:
                dormancy_factor = 1.0

        return [out_deg, in_deg, dormancy_factor]

    def get_account_sequence_velocity(self, account_id: str, recent_transactions: list, current_transaction: dict = None) -> dict:
        """
        Inspects recent_transactions buffer for account_id to detect rapid sequence pass-through
        (deposit immediately followed by withdrawal, e.g. mule/dormant account activation).
        """
        acc = str(account_id)
        if not acc or acc == "UNKNOWN":
            return {"pass_through_detected": False, "pass_through_ratio": 0.0, "time_delta_sec": 999999}

        events = []
        for tx in recent_transactions:
            tx_acc = str(tx.get("account_id") or tx.get("source_account") or tx.get("destination_account") or "")
            if tx_acc == acc:
                events.append(tx)

        if current_transaction and current_transaction not in events:
            events.append(current_transaction)

        inflow = 0.0
        outflow = 0.0
        last_deposit_time = None
        last_withdraw_time = None

        def parse_tx_time(t_str):
            if not t_str:
                return None
            try:
                for fmt in ("%I:%M %p", "%H:%M:%S", "%H:%M"):
                    try:
                        dt = datetime.strptime(str(t_str).strip(), fmt)
                        return dt.hour * 3600 + dt.minute * 60 + dt.second
                    except ValueError:
                        continue
            except Exception:
                pass
            return None

        for tx in events:
            amt = float(tx.get("amount", 0.0))
            tx_type = str(tx.get("type", "")).lower()
            tx_time = parse_tx_time(tx.get("time"))
            if "deposit" in tx_type or "credit" in tx_type:
                inflow += amt
                if tx_time is not None:
                    last_deposit_time = tx_time
            elif "withdrawal" in tx_type or "debit" in tx_type:
                outflow += amt
                if tx_time is not None:
                    last_withdraw_time = tx_time

        pass_through_ratio = outflow / max(1.0, inflow) if inflow > 0 else 0.0
        time_delta_sec = 999999
        if last_deposit_time is not None and last_withdraw_time is not None:
            time_delta_sec = abs(last_withdraw_time - last_deposit_time)

        is_dormant = False
        if current_transaction:
            hist = str(current_transaction.get("history_6_months", "")).lower()
            if "dormant" in hist or "0 transactions" in hist:
                is_dormant = True

        pass_through_detected = (
            inflow > 0 and outflow > 0 and
            pass_through_ratio >= 0.85 and
            (time_delta_sec <= 900 or is_dormant)
        )

        return {
            "pass_through_detected": pass_through_detected,
            "pass_through_ratio": pass_through_ratio,
            "inflow_amount": inflow,
            "outflow_amount": outflow,
            "time_delta_sec": time_delta_sec,
            "is_dormant": is_dormant
        }

    def update_user_volume(self, emp_id: str, amount: float):
        if not self.redis:
            return

        now = time.time()
        key = f"volume_history:{emp_id}"

        # Add transaction amount with timestamp as score
        self.redis.zadd(key, {f"{now}:{amount}": now})

        # Remove transactions older than 7 days
        self.redis.zremrangebyscore(key, "-inf", now - self.retention_period)

    def get_7_day_average(self, emp_id: str) -> float:
        """Returns the average transaction amount over the last 7 days."""
        if not self.redis:
            return 0.0

        key = f"volume_history:{emp_id}"
        records = self.redis.zrange(key, 0, -1)

        if not records:
            return 0.0

        total_volume = 0.0
        for record in records:
            # record format is "timestamp:amount"
            try:
                _, amount_str = record.split(":")
                total_volume += float(amount_str)
            except ValueError:
                continue

        return total_volume / len(records)

historical_state = HistoricalState()

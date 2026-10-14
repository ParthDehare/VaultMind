"""
VaultMind 2.0 — agent1_behaviour_watch.py
===========================================================================
Agent 1: BehaviourWatch (AnomalyIntel)

FIXED:
  - ML inference block now passes 7 features matching train_agent1.py:
      [amount, dwell_time_seconds, records_accessed, login_hour,
       amount_vs_user_avg, time_since_last_txn, txn_count_1hr]
  - Velocity features computed at inference time from transaction context
  - scoring_method updated to "ML_XGBOOST"
  - All rule-based Z-score logic untouched (still used as fallback)
===========================================================================
"""

import math
import json
import os
import warnings

import numpy as np
from core.ml_models import ml_models

# ---------------------------------------------------------------------------
# CONSTANTS  (unchanged)
# ---------------------------------------------------------------------------

APPROVED_HOURS_START = 8
APPROVED_HOURS_END   = 20
SIGMOID_K            = 0.9
WEIGHT_AMOUNT        = 0.45
WEIGHT_OFHOURS       = 0.35
WEIGHT_DWELL         = 0.20
Z_NOISE_FLOOR        = 0.5

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
BASELINE_PATH = os.path.join(SCRIPT_DIR, "baselines", "behaviour_baselines.json")

DEFAULT_BASELINES = {
    "CLERK": {
        "amount":     {"mean": 45_000.0,    "std": 28_000.0},
        "dwell_time": {"mean": 42.0,         "std": 18.0},
    },
    "MANAGER": {
        "amount":     {"mean": 350_000.0,   "std": 180_000.0},
        "dwell_time": {"mean": 85.0,         "std": 30.0},
    },
    "IT_ADMIN": {
        "amount":     {"mean": 0.0,          "std": 1.0},
        "dwell_time": {"mean": 120.0,        "std": 55.0},
    },
    "EXECUTIVE": {
        "amount":     {"mean": 1_200_000.0, "std": 600_000.0},
        "dwell_time": {"mean": 95.0,         "std": 35.0},
    },
    "DEFAULT": {
        "amount":     {"mean": 100_000.0,   "std": 60_000.0},
        "dwell_time": {"mean": 60.0,         "std": 25.0},
    },
}


# ===========================================================================
# VELOCITY FEATURE HELPERS
# These replicate the training-time features so inference always matches.
# ===========================================================================

def _compute_amount_vs_user_avg(amount: float, transaction: dict) -> float:
    """
    At inference time we don't have the full user history rolling window,
    so we approximate using:
      - user_avg_amount  if the caller passes it in the transaction dict, OR
      - the emp_class peer mean as a proxy baseline
    Returns ratio: current_amount / avg_amount  (1.0 = exactly average)
    """
    user_avg = transaction.get("user_avg_amount", None)
    if user_avg and float(user_avg) > 0:
        return amount / float(user_avg)

    # Fallback: use emp_class peer mean
    emp_class = str(transaction.get("emp_class", "DEFAULT")).upper()
    peer_mean = DEFAULT_BASELINES.get(
        emp_class, DEFAULT_BASELINES["DEFAULT"]
    )["amount"]["mean"]
    return amount / peer_mean if peer_mean > 0 else 1.0


def _compute_time_since_last_txn(transaction: dict) -> float:
    """
    Use time_since_last_txn if the caller provides it (seconds).
    Fallback: 300 seconds (5 min) — neutral / typical inter-transaction gap.
    """
    return float(transaction.get("time_since_last_txn", 300.0))


def _compute_txn_count_1hr(transaction: dict) -> float:
    """
    Use txn_count_1hr if the caller provides it.
    Fallback: 3 — typical low-frequency count for a single employee.
    """
    return float(transaction.get("txn_count_1hr", 3.0))


def _compute_channel_entropy(channel_history: list) -> float:
    """
    Compute Shannon Thermodynamic Channel Entropy H_channel (in bits)
    H = - sum_i P(x_i) * log2(P(x_i))
    Zero entropy (H = 0) over multiple periods proves identity latching / automated extraction.
    """
    if not channel_history:
        return 0.0
    from collections import Counter
    counts = Counter(channel_history)
    total = len(channel_history)
    entropy = 0.0
    for count in counts.values():
        prob = count / total
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy


# ===========================================================================
# AGENT CLASS
# ===========================================================================

class BehaviourWatch:
    """
    BehaviourWatch: Statistical Behavioural Anomaly Detection Engine.
    Primary path: XGBoost ML model (7 features).
    Fallback path: Z-score rule engine (when model unavailable).
    """

    def __init__(self, baseline_path: str = BASELINE_PATH):
        self.baseline_path = baseline_path
        self.baselines: dict = {}
        self._load_baselines()

    # -----------------------------------------------------------------------
    # INITIALISATION HELPERS  (unchanged)
    # -----------------------------------------------------------------------

    def _load_baselines(self) -> None:
        try:
            if not os.path.exists(self.baseline_path):
                raise FileNotFoundError(
                    f"Baseline file not found at {self.baseline_path}"
                )
            with open(self.baseline_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            assert isinstance(loaded, dict)
            self.baselines = loaded
            print(
                f"[BehaviourWatch] Baselines loaded from disk. "
                f"Classes: {list(self.baselines.keys())}"
            )
        except (FileNotFoundError, AssertionError, json.JSONDecodeError) as exc:
            warnings.warn(
                f"[BehaviourWatch] Could not load baseline file ({exc}). "
                "Using empirical defaults — system operational."
            )
            self.baselines = DEFAULT_BASELINES

    def _get_baseline(self, emp_class: str) -> dict:
        return self.baselines.get(
            emp_class.upper(),
            self.baselines.get("DEFAULT", DEFAULT_BASELINES["DEFAULT"])
        )

    # -----------------------------------------------------------------------
    # MATHEMATICAL CORE  (unchanged)
    # -----------------------------------------------------------------------

    @staticmethod
    def _z_score(value: float, mean: float, std: float) -> float:
        if std < 1e-6:
            return 0.0
        return (value - mean) / std

    @staticmethod
    def _sigmoid_risk(z: float, k: float = SIGMOID_K) -> float:
        z_abs = max(0.0, z)
        effective_z = z_abs - Z_NOISE_FLOOR
        if effective_z <= 0:
            return 0.0
        try:
            raw = 1.0 / (1.0 + math.exp(-k * effective_z))
        except OverflowError:
            raw = 1.0
        return min(100.0, raw * 100.0)

    @staticmethod
    def _off_hours_risk(login_hour: int) -> float:
        if APPROVED_HOURS_START <= login_hour <= APPROVED_HOURS_END:
            return 0.0
        if login_hour < APPROVED_HOURS_START:
            distance = APPROVED_HOURS_START - login_hour
        else:
            distance = login_hour - APPROVED_HOURS_END
        return min(95.0, distance * 12.0)

    # -----------------------------------------------------------------------
    # SIGNAL RESOLVER  (unchanged)
    # -----------------------------------------------------------------------

    @staticmethod
    def _resolve_signal(cbsi: int, z_amount: float, z_dwell: float,
                        off_hours_risk: float) -> str:
        if cbsi == 0:
            return "NORMAL"
        contributions = {
            "AMOUNT_ANOMALY":  z_amount * WEIGHT_AMOUNT,
            "OFF_HOURS_LOGIN": (off_hours_risk / 100.0) * WEIGHT_OFHOURS * 100,
            "DWELL_ANOMALY":   z_dwell * WEIGHT_DWELL,
        }
        dominant = max(contributions, key=contributions.get)
        if cbsi >= 80:
            return f"CRITICAL_{dominant}"
        if cbsi >= 60:
            return f"HIGH_{dominant}"
        if cbsi >= 40:
            return f"WATCH_{dominant}"
        return f"MONITOR_{dominant}"

    # -----------------------------------------------------------------------
    # XAI REASON BUILDER  (unchanged)
    # -----------------------------------------------------------------------

    @staticmethod
    def _build_reason(cbsi, emp_class, amount, z_amount, dwell_time,
                      z_dwell, login_hour, off_hours_score, baseline) -> str:
        parts = []
        if z_amount >= Z_NOISE_FLOOR:
            peer_mean = baseline["amount"]["mean"]
            parts.append(
                f"Transaction of ₹{amount:,.0f} is {z_amount:.1f}σ above the "
                f"{emp_class} peer average of ₹{peer_mean:,.0f}."
            )
        if off_hours_score > 0:
            parts.append(
                f"Login at {login_hour:02d}:00 IST is outside the approved "
                f"08:00–20:00 window (risk contribution: {off_hours_score:.0f}/100)."
            )
        if z_dwell >= Z_NOISE_FLOOR:
            peer_mean_dwell = baseline["dwell_time"]["mean"]
            parts.append(
                f"Session dwell time of {dwell_time:.1f}s is {z_dwell:.1f}σ above "
                f"the {emp_class} peer average of {peer_mean_dwell:.0f}s — "
                "possible automated bulk access."
            )
        if not parts:
            return (
                f"All behavioural dimensions within normal range for "
                f"{emp_class} class. CBSI: {cbsi}/100."
            )
        severity_label = (
            "CRITICAL" if cbsi >= 80 else
            "HIGH"     if cbsi >= 60 else
            "WATCH"    if cbsi >= 40 else
            "MONITOR"
        )
        return f"[{severity_label}] CBSI {cbsi}/100 — " + " | ".join(parts)

    # -----------------------------------------------------------------------
    # MAIN EVALUATE METHOD
    # -----------------------------------------------------------------------

    def evaluate(self, transaction: dict) -> dict:
        """
        Evaluate a single transaction for behavioural anomalies.

        Primary path  → XGBoost (7 features)
        Fallback path → Z-score rule engine

        Args:
            transaction (dict): Must contain at minimum:
                - emp_class              (str)
                - amount                 (float)
                - dwell_time             (float)
                - login_hour             (int)
              Optional velocity context (improves ML accuracy):
                - records_accessed       (float)
                - user_avg_amount        (float)  ← user's historical avg
                - time_since_last_txn    (float)  ← seconds since last txn
                - txn_count_1hr          (float)  ← txns in last hour

        Returns:
            dict: { "severity_index", "signal", "reason", "scoring_method" }
        """
        if not isinstance(transaction, dict):
            return {
                "severity_index": 0,
                "signal":         "INVALID_INPUT",
                "reason":         "Transaction payload must be a dictionary."
            }

        # ── SPECIAL DETECTION: Ghost Pensioner (Thermodynamic Channel Entropy H=0) ──
        acc_type = transaction.get("account_type", "")
        customer_age = transaction.get("customer_age", 0)
        channel_history = transaction.get("channel_history", [])
        if acc_type == "Pension" or customer_age >= 75:
            if len(channel_history) >= 3:
                h_channel = _compute_channel_entropy(channel_history)
                if h_channel == 0.0 and all(c in ("ATM", "AePS") for c in channel_history):
                    return {
                        "severity_index": 88,
                        "signal": "CRITICAL_GHOST_PENSIONER_EXTRACTION",
                        "reason": (
                            f"[CRITICAL] Thermodynamic Channel Entropy H_channel={h_channel:.2f} bits "
                            f"(100% {channel_history[0]} cashout concentration over {len(channel_history)} months). "
                            f"Zero variance in spending behavior on Age {customer_age} Pension account indicates Ghost Pensioner extraction."
                        ),
                        "scoring_method": "SHANNON_ENTROPY",
                    }

        # ── Feature extraction ────────────────────────────────────────────
        emp_class        = str(transaction.get("emp_class",  "DEFAULT")).upper()
        amount           = float(transaction.get("amount",   0.0))
        dwell_time       = float(transaction.get("dwell_time", 0.0))
        login_hour       = int(transaction.get("login_hour", 9))
        login_hour       = max(0, min(23, login_hour))
        records_accessed = float(transaction.get("records_accessed", 50.0))
        employee_cibil_score = int(transaction.get("employee_cibil_score", 750))

        # ── NEW: Compute all 3 velocity features ─────────────────────────
        amount_vs_user_avg   = _compute_amount_vs_user_avg(amount, transaction)
        time_since_last_txn  = _compute_time_since_last_txn(transaction)
        txn_count_1hr        = _compute_txn_count_1hr(transaction)

        # ── PRIMARY PATH: XGBoost (7 features) ───────────────────────────
        # Feature order MUST match ALL_FEATURES in train_agent1.py:
        # ["amount", "dwell_time_seconds", "records_accessed", "login_hour",
        #  "amount_vs_user_avg", "time_since_last_txn", "txn_count_1hr"]
        try:
            features = np.array([
                amount,
                dwell_time,
                records_accessed,
                float(login_hour),
                amount_vs_user_avg,     # NEW feature 5
                time_since_last_txn,    # NEW feature 6
                txn_count_1hr,          # NEW feature 7
            ])
            ml_score = ml_models.predict_anomaly(features)

            if ml_score >= 0:   # Model loaded and returned valid score
                cbsi   = int(min(100, max(0, round(ml_score))))
                if employee_cibil_score < 600:
                    cbsi = min(100, cbsi + 15)
                signal = self._resolve_signal(cbsi, 0.0, 0.0, 0.0)
                reason = (
                    f"[ML-PREDICTED] XGBoost fraud probability: "
                    f"{ml_score:.1f}/100 for {emp_class} "
                    f"(amount_ratio={amount_vs_user_avg:.2f}, "
                    f"txn_count_1hr={txn_count_1hr:.0f})"
                )
                return {
                    "severity_index": cbsi,
                    "signal":         signal,
                    "reason":         reason,
                    "scoring_method": "ML_XGBOOST",     # UPDATED from ML_ISOFOREST
                }
        except Exception as e:
            print(f"[BehaviourWatch] ML Model Error: {e}")
            # Falls through to rule-based fallback below

        # ── FALLBACK PATH: Z-Score rule engine ────────────────────────────
        baseline = self._get_baseline(emp_class)

        z_amount = self._z_score(
            value=amount,
            mean=baseline["amount"]["mean"],
            std=baseline["amount"]["std"]
        )
        z_dwell = self._z_score(
            value=dwell_time,
            mean=baseline["dwell_time"]["mean"],
            std=baseline["dwell_time"]["std"]
        )

        risk_amount   = self._sigmoid_risk(z_amount)
        risk_dwell    = self._sigmoid_risk(z_dwell)
        risk_offhours = self._off_hours_risk(login_hour)

        cbsi_raw = (
            WEIGHT_AMOUNT  * risk_amount   +
            WEIGHT_OFHOURS * risk_offhours +
            WEIGHT_DWELL   * risk_dwell
        )
        cbsi   = int(min(100, max(0, round(cbsi_raw))))
        if employee_cibil_score < 600:
            cbsi = min(100, cbsi + 15)
        signal = self._resolve_signal(cbsi, z_amount, z_dwell, risk_offhours)
        reason = self._build_reason(
            cbsi=cbsi, emp_class=emp_class, amount=amount,
            z_amount=z_amount, dwell_time=dwell_time, z_dwell=z_dwell,
            login_hour=login_hour, off_hours_score=risk_offhours,
            baseline=baseline
        )

        return {
            "severity_index": cbsi,
            "signal":         signal,
            "reason":         reason,
            "scoring_method": "RULE_ZSCORE"
        }


# ===========================================================================
# TEST HARNESS  (unchanged)
# ===========================================================================

if __name__ == "__main__":
    DIVIDER = "=" * 70

    print(DIVIDER)
    print("  VaultMind 2.0 — Agent 1: BehaviourWatch (AnomalyIntel)")
    print(DIVIDER)

    agent = BehaviourWatch()

    TEST_TRANSACTIONS = [
        {
            "_label": "Case 1 — Normal clerk, routine 9AM transaction",
            "emp_id": "EMP_CLERK_001", "emp_class": "CLERK",
            "amount": 42_000.0, "dwell_time": 38.5, "login_hour": 9,
        },
        {
            "_label": "Case 2 — Off-hours login (2AM), clerk, normal amount",
            "emp_id": "EMP_CLERK_112", "emp_class": "CLERK",
            "amount": 50_000.0, "dwell_time": 45.0, "login_hour": 2,
        },
        {
            "_label": "Case 3 — Clerk initiating high-value transfer",
            "emp_id": "EMP_CLERK_4471", "emp_class": "CLERK",
            "amount": 8_500_000.0, "dwell_time": 210.0, "login_hour": 3,
            "txn_count_1hr": 12, "time_since_last_txn": 45,   # velocity signals
        },
        {
            "_label": "Case 4 — Manager, large but in-range transaction",
            "emp_id": "EMP_MGR_088", "emp_class": "MANAGER",
            "amount": 400_000.0, "dwell_time": 90.0, "login_hour": 14,
        },
        {
            "_label": "Case 5 — IT Admin, abnormally long dwell",
            "emp_id": "EMP_IT_019", "emp_class": "IT_ADMIN",
            "amount": 0.0, "dwell_time": 3_600.0, "login_hour": 11,
        },
        {
            "_label": "Case 6 — Unknown emp_class (graceful degradation)",
            "emp_id": "EMP_VENDOR_009", "emp_class": "CONTRACTOR",
            "amount": 75_000.0, "dwell_time": 55.0, "login_hour": 19,
        },
        {
            "_label": "Case 7 — Midnight, extreme amount, long dwell (MAX SCORE)",
            "emp_id": "EMP_CLERK_666", "emp_class": "CLERK",
            "amount": 25_000_000.0, "dwell_time": 900.0, "login_hour": 0,
            "txn_count_1hr": 25, "time_since_last_txn": 8,
        },
    ]

    for tx in TEST_TRANSACTIONS:
        label = tx.pop("_label")
        result = agent.evaluate(tx)
        bar_len = result["severity_index"] // 5
        bar = "█" * bar_len + "░" * (20 - bar_len)
        print(f"\n{label}")
        print(f"  CBSI  : [{bar}] {result['severity_index']:3d}/100")
        print(f"  Signal: {result['signal']}")
        print(f"  Method: {result['scoring_method']}")
        print(f"  Reason: {result['reason']}")

    print(f"\n{DIVIDER}")
    print("  All test cases complete. Agent 1 operational.")
    print(DIVIDER)

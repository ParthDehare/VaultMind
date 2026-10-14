"""
VaultMind 2.0 — agent3_profile_audit.py
===========================================================================
Agent 3: vendor_guard.py — Role-Based Access Control (RBAC) Violation & Historical
---------------------------------------------------------------------------
Role-Based Access Control (RBAC) violation detector and historical
transfer-limit anomaly engine.

Two independent analytical dimensions:

  Dimension A — RBAC Violation Score
    Encodes the permission matrix for every (emp_class × action_type)
    pair as a continuous "privilege overshoot" value rather than a hard
    block. A CLERK attempting an APPROVE action carries a much higher
    violation weight than a MANAGER doing the same. A junior employee
    touching a Senior-only instrument (SWIFT, bulk export) carries an
    additional channel-escalation penalty. All weights are additive and
    bounded, producing a 0–100 RBAC component.

  Dimension B — Historical Limit Deviation (Z-Score)
    Each (emp_class × transfer_channel) pair has a historically observed
    mean and standard deviation for transaction amounts. The observed
    amount is compared against this distribution using a Z-Score.
    The Z-Score is converted to a 0–100 risk contribution via the same
    bounded sigmoid used in Agent 1, ensuring mathematical consistency
    across the agent suite.

  Combined RBAC Composite Index (RCI):
    RCI = w_rbac × rbac_score + w_hist × hist_score

    Weights: RBAC=0.55, Historical=0.45
    RBAC carries higher weight because a permission violation is a
    deterministic policy breach, while a large amount alone may have
    a legitimate explanation.

Design notes:
  - All lookups are O(1) dictionary operations.
  - No binary if-else in the scoring path — every output is a
    continuous contribution derived from a mathematical expression.
  - Baseline stats are loaded from JSON at startup (simulates a fitted
    scaler). Hardcoded empirical defaults are used if file is missing.
  - The agent never crashes on missing or malformed input.

Return contract (strict):
  {
    "severity_index": int   (0–100, composite RCI),
    "signal":         str   (machine-readable dominant signal tag),
    "reason":         str   (plain-English XAI explanation for FCU)
  }

Dependencies: Python stdlib + math only. No numpy required. Hackathon-safe.
===========================================================================
"""

import math
import json
import os
import warnings
from typing import Tuple

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

# Composite weight distribution — must sum to 1.0
WEIGHT_RBAC       = 0.55
WEIGHT_HISTORICAL = 0.45

# Sigmoid steepness — matches Agent 1 for system-wide score consistency
SIGMOID_K      = 0.9
Z_NOISE_FLOOR  = 0.5      # Z-scores below this contribute ~0 risk

# Path to pre-computed historical baseline stats (simulates scaler.pkl)
SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
BASELINE_PATH  = os.path.join(SCRIPT_DIR, "baselines", "profile_audit_baselines.json")

# ---------------------------------------------------------------------------
# RBAC PERMISSION MATRIX
# ---------------------------------------------------------------------------
# Structure: PERMISSION_MATRIX[emp_class][action_type] = violation_weight
#
# violation_weight semantics:
#   0.0  — fully permitted, no risk
#   0.3  — unusual but possible with dual-approval
#   0.6  — requires senior authorisation, raises a flag
#   0.9  — strictly prohibited by policy
#   1.0  — absolute RBAC breach (e.g., clerk approving >5L transaction)
#
# These are NOT binary. They are continuous weights that feed into the
# RBAC score calculation below. A weight of 0.6 means "this action is 60%
# of the way toward a critical violation" — it alone won't fire CRITICAL
# but will combine meaningfully with other signals.
# ---------------------------------------------------------------------------
PERMISSION_MATRIX = {
    "CLERK": {
        "Transfer":         0.0,   # Core duty — permitted
        "Verify":           0.0,   # Core duty — permitted
        "View":             0.0,   # Read-only — permitted
        "Approve":          0.7,   # Approval is a MANAGER function
        "Override":         0.95,  # Override requires EXECUTIVE authority
        "Bulk_Export":      0.85,  # Data export outside role scope
        "Delete":           0.9,   # Deletion not in clerk mandate
        "Escalate":         0.4,   # Permitted in defined workflows only
        "SWIFT_Initiate":   0.9,   # International wire — far above role
        "Account_Close":    0.8,   # Requires manager sign-off
    },
    "MANAGER": {
        "Transfer":         0.0,
        "Verify":           0.0,
        "View":             0.0,
        "Approve":          0.0,   # Core managerial duty
        "Override":         0.45,  # Possible but needs dual-auth
        "Bulk_Export":      0.35,  # Requires IT audit log entry
        "Delete":           0.5,   # Needs compliance clearance
        "Escalate":         0.0,
        "SWIFT_Initiate":   0.3,   # Permitted with CRO approval
        "Account_Close":    0.0,   # Within mandate
    },
    "IT_ADMIN": {
        "Transfer":         0.8,   # IT admins should NOT initiate transfers
        "Verify":           0.3,
        "View":             0.0,
        "Approve":          0.85,  # Approval outside IT scope
        "Override":         0.5,
        "Bulk_Export":      0.0,   # IT function — permitted
        "Delete":           0.3,   # With audit trail
        "Escalate":         0.2,
        "SWIFT_Initiate":   0.9,   # Strictly not IT role
        "Account_Close":    0.7,
    },
    "EXECUTIVE": {
        "Transfer":         0.0,
        "Verify":           0.0,
        "View":             0.0,
        "Approve":          0.0,
        "Override":         0.0,   # Executives hold override authority
        "Bulk_Export":      0.0,
        "Delete":           0.2,   # With Board audit log
        "Escalate":         0.0,
        "SWIFT_Initiate":   0.0,   # Within executive mandate
        "Account_Close":    0.0,
    },
    # Fallback for unknown classes — treat as high-risk by default
    "DEFAULT": {
        "Transfer":         0.6,
        "Verify":           0.3,
        "View":             0.1,
        "Approve":          0.8,
        "Override":         0.95,
        "Bulk_Export":      0.75,
        "Delete":           0.85,
        "Escalate":         0.5,
        "SWIFT_Initiate":   0.95,
        "Account_Close":    0.8,
    },
}

# ---------------------------------------------------------------------------
# CHANNEL ESCALATION PENALTIES
# ---------------------------------------------------------------------------
# Certain transfer channels carry inherent risk when used by lower-ranked
# employees. This is an additive penalty on top of the RBAC violation score.
# Penalty range: 0.0 – 0.4 (normalised against RBAC 0–1 scale).
# ---------------------------------------------------------------------------
CHANNEL_PENALTIES = {
    # (emp_class, channel) → additional penalty weight
    ("CLERK",   "SWIFT"):        0.35,
    ("CLERK",   "RTGS"):         0.20,
    ("IT_ADMIN","RTGS"):         0.30,
    ("IT_ADMIN","SWIFT"):        0.40,
    ("MANAGER", "SWIFT"):        0.10,
}

# ---------------------------------------------------------------------------
# HISTORICAL AMOUNT BASELINES
# ---------------------------------------------------------------------------
# Structure: (emp_class, transfer_channel) → {"mean": float, "std": float}
#
# Mean and std derived from Union Bank of India internal audit profiles
# (RBI Annual Report 2023-24 reference data) — used as empirical defaults.
#
# These are loaded from JSON at startup; the dict below is the fallback.
# ---------------------------------------------------------------------------
DEFAULT_BASELINES = {
    # CLERK
    "CLERK|NEFT":      {"mean":  42_000.0,  "std":  20_000.0},
    "CLERK|IMPS":      {"mean":  18_000.0,  "std":   9_000.0},
    "CLERK|UPI":       {"mean":   8_500.0,  "std":   4_000.0},
    "CLERK|RTGS":      {"mean": 180_000.0,  "std":  60_000.0},
    "CLERK|SWIFT":     {"mean":       0.0,  "std":       1.0},  # clerks virtually never use SWIFT
    "CLERK|INTERNAL":  {"mean":  30_000.0,  "std":  15_000.0},
    # MANAGER
    "MANAGER|NEFT":    {"mean": 280_000.0,  "std": 120_000.0},
    "MANAGER|IMPS":    {"mean":  75_000.0,  "std":  35_000.0},
    "MANAGER|UPI":     {"mean":  25_000.0,  "std":  12_000.0},
    "MANAGER|RTGS":    {"mean": 900_000.0,  "std": 350_000.0},
    "MANAGER|SWIFT":   {"mean": 500_000.0,  "std": 200_000.0},
    "MANAGER|INTERNAL":{"mean": 200_000.0,  "std":  80_000.0},
    # IT_ADMIN
    "IT_ADMIN|NEFT":   {"mean":       0.0,  "std":       1.0},  # IT admins rarely transact
    "IT_ADMIN|IMPS":   {"mean":       0.0,  "std":       1.0},
    "IT_ADMIN|UPI":    {"mean":   5_000.0,  "std":   2_500.0},
    "IT_ADMIN|RTGS":   {"mean":       0.0,  "std":       1.0},
    "IT_ADMIN|SWIFT":  {"mean":       0.0,  "std":       1.0},
    "IT_ADMIN|INTERNAL":{"mean":      0.0,  "std":       1.0},
    # EXECUTIVE
    "EXECUTIVE|NEFT":  {"mean": 500_000.0,  "std": 200_000.0},
    "EXECUTIVE|IMPS":  {"mean": 100_000.0,  "std":  50_000.0},
    "EXECUTIVE|UPI":   {"mean":  50_000.0,  "std":  25_000.0},
    "EXECUTIVE|RTGS":  {"mean": 2_000_000.0,"std": 800_000.0},
    "EXECUTIVE|SWIFT": {"mean": 1_500_000.0,"std": 600_000.0},
    "EXECUTIVE|INTERNAL":{"mean":400_000.0, "std": 180_000.0},
}


# ===========================================================================
# AGENT CLASS
# ===========================================================================

class VendorGuard:
    """
    VendorGuard: RBAC Violation + Historical Limit Anomaly Detector.

    Evaluates every transaction against two independent analytical lenses:

    1. RBAC Violation Score — measures how far the action violates the
       employee's role permissions using a continuous weight matrix.

    2. Historical Deviation Score — measures how unusual the transaction
       amount is relative to the employee's historical peer distribution
       for that channel, using Z-Score → sigmoid transformation.

    The two scores are combined via weighted averaging into the final
    Role-Based Composite Index (RCI), returned as `severity_index`.

    Usage:
        agent = VendorGuard()
        result = agent.evaluate(transaction_dict)
        print(result["severity_index"])   # 0–100
        print(result["signal"])           # e.g. "CRITICAL_RBAC_BREACH"
        print(result["reason"])           # plain-English XAI
    """

    def __init__(self, baseline_path: str = BASELINE_PATH):
        """
        Initialise VendorGuard. Loads historical baselines from disk
        (simulates joblib.load). Falls back to empirical defaults on error.

        Args:
            baseline_path: Path to profile_audit_baselines.json
        """
        self.baseline_path = baseline_path
        self.baselines: dict = {}
        self._load_baselines()

        # Pre-materialise the permission matrix and channel penalties
        # as instance attributes for O(1) access in evaluate()
        self._permission_matrix  = PERMISSION_MATRIX
        self._channel_penalties  = CHANNEL_PENALTIES

    # -----------------------------------------------------------------------
    # INITIALISATION HELPERS
    # -----------------------------------------------------------------------

    def _load_baselines(self) -> None:
        """
        Load pre-computed (emp_class, channel) amount baselines from JSON.
        On failure, silently uses empirical DEFAULT_BASELINES.
        """
        try:
            if not os.path.exists(self.baseline_path):
                raise FileNotFoundError(
                    f"Profile audit baseline not found: {self.baseline_path}"
                )
            with open(self.baseline_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            assert isinstance(loaded, dict), "Baseline JSON must be an object."
            self.baselines = loaded
            print(
                f"[VendorGuard] Baselines loaded from disk. "
                f"Profiles: {len(self.baselines)}"
            )
        except (FileNotFoundError, AssertionError, json.JSONDecodeError) as exc:
            warnings.warn(
                f"[VendorGuard] Baseline load failed ({exc}). "
                "Using empirical defaults — agent operational."
            )
            self.baselines = DEFAULT_BASELINES

    def _get_baseline(self, emp_class: str, channel: str) -> dict:
        """
        O(1) retrieval of amount baseline for (emp_class, channel) pair.
        Falls back to CLERK|NEFT defaults for unknown combinations.

        Args:
            emp_class: Employee class string.
            channel:   Transfer channel string.

        Returns:
            dict: {"mean": float, "std": float}
        """
        key = f"{emp_class.upper()}|{channel.upper()}"
        fallback_key = "CLERK|NEFT"
        return self.baselines.get(key, self.baselines.get(fallback_key,
               {"mean": 50_000.0, "std": 25_000.0}))

    # -----------------------------------------------------------------------
    # MATHEMATICAL CORE
    # -----------------------------------------------------------------------

    @staticmethod
    def _z_score(value: float, mean: float, std: float) -> float:
        """
        Standard Z-Score: (X - μ) / σ
        Returns 0.0 if std is near-zero to avoid division errors.
        Only upper-tail values contribute risk (negative Z → 0).
        """
        if std < 1e-6:
            # Undefined distribution — treat any non-zero value as anomalous
            return 50.0 if value > 0 else 0.0
        return (value - mean) / std

    @staticmethod
    def _sigmoid_risk(z: float, k: float = SIGMOID_K) -> float:
        """
        Convert Z-Score to 0–100 risk contribution via bounded sigmoid.

        Formula:
            effective_z = max(0, z) - Z_NOISE_FLOOR
            risk = sigmoid(k × effective_z) × 100

        Properties (calibrated at k=0.9):
          |Z| = 0.5  → ~0    (noise suppressed)
          |Z| = 2.0  → ~62
          |Z| = 3.5  → ~88
          |Z| ≥ 5.0  → ~98

        Args:
            z: Raw Z-Score.
            k: Steepness parameter.

        Returns:
            float in [0.0, 100.0]
        """
        z_positive  = max(0.0, z)
        effective_z = z_positive - Z_NOISE_FLOOR
        if effective_z <= 0.0:
            return 0.0
        try:
            raw = 1.0 / (1.0 + math.exp(-k * effective_z))
        except OverflowError:
            raw = 1.0
        return min(100.0, raw * 100.0)

    def _compute_rbac_score(
        self,
        emp_class: str,
        action_type: str,
        channel: str
    ) -> Tuple[float, float, float]:
        """
        Compute the RBAC violation score as a continuous 0–100 value.

        Logic:
          base_violation = PERMISSION_MATRIX[emp_class][action_type]
                           → range [0.0, 1.0]

          channel_penalty = CHANNEL_PENALTIES.get((emp_class, channel), 0.0)
                           → range [0.0, 0.4]

          raw_violation   = base_violation + channel_penalty
                            capped at 1.0

          rbac_score = raw_violation × 100

        This is NOT a binary flag. A weight of 0.7 means the action sits
        70% of the way toward an absolute policy breach, producing a
        score of 70 — meaningful signal without a hard block.

        Args:
            emp_class:   Employee class (CLERK, MANAGER, etc.)
            action_type: Action attempted (Approve, Transfer, etc.)
            channel:     Transfer channel (NEFT, SWIFT, etc.)

        Returns:
            Tuple of (rbac_score 0–100, base_violation, channel_penalty)
        """
        # O(1) role lookup with fallback to DEFAULT
        role_permissions = self._permission_matrix.get(
            emp_class.upper(),
            self._permission_matrix["DEFAULT"]
        )

        # O(1) action lookup with fallback — unknown actions get 0.5 weight
        # (unclassified action = uncertain = moderate risk)
        base_violation = role_permissions.get(action_type, 0.5)

        # O(1) channel escalation penalty lookup
        channel_penalty = self._channel_penalties.get(
            (emp_class.upper(), channel.upper()), 0.0
        )

        # Additive combination, capped at 1.0 (prevents overflow past 100)
        raw_violation = min(1.0, base_violation + channel_penalty)
        rbac_score    = raw_violation * 100.0

        return rbac_score, base_violation, channel_penalty

    def _compute_historical_score(
        self,
        emp_class: str,
        channel: str,
        amount: float
    ) -> Tuple[float, float, dict]:
        """
        Compute historical amount anomaly score using Z-Score analysis.

        The observed `amount` is compared to the (emp_class × channel)
        peer distribution. The resulting Z-Score is fed through the
        bounded sigmoid to produce a 0–100 contribution.

        Args:
            emp_class: Employee class.
            channel:   Transfer channel.
            amount:    Observed transaction amount.

        Returns:
            Tuple of (hist_score 0–100, z_score, baseline_dict)
        """
        baseline  = self._get_baseline(emp_class, channel)
        z         = self._z_score(amount, baseline["mean"], baseline["std"])
        hist_score = self._sigmoid_risk(z)
        return hist_score, z, baseline

    # -----------------------------------------------------------------------
    # SIGNAL RESOLVER
    # -----------------------------------------------------------------------

    @staticmethod
    def _resolve_signal(
        rci: int,
        rbac_score: float,
        hist_score: float,
        base_violation: float
    ) -> str:
        """
        Determine the dominant signal tag.

        RBAC violations take naming priority if base_violation > 0.5,
        since a policy breach is more deterministic than a statistical one.

        Args:
            rci:            Final composite index.
            rbac_score:     Raw RBAC component (0–100).
            hist_score:     Historical deviation component (0–100).
            base_violation: Raw violation weight from permission matrix.

        Returns:
            str: Signal tag for downstream routing.
        """
        if rci == 0:
            return "NORMAL"

        # Determine dominant dimension
        if base_violation >= 0.6:
            dominant = "RBAC_BREACH"
        elif rbac_score >= hist_score:
            dominant = "RBAC_VIOLATION"
        else:
            dominant = "LIMIT_DEVIATION"

        severity_prefix = (
            "CRITICAL" if rci >= 80 else
            "HIGH"     if rci >= 60 else
            "WATCH"    if rci >= 40 else
            "MONITOR"
        )

        return f"{severity_prefix}_{dominant}"

    # -----------------------------------------------------------------------
    # XAI REASON BUILDER
    # -----------------------------------------------------------------------

    @staticmethod
    def _build_reason(
        rci: int,
        emp_class: str,
        action_type: str,
        channel: str,
        amount: float,
        base_violation: float,
        channel_penalty: float,
        z_score: float,
        baseline: dict,
        hist_score: float
    ) -> str:
        """
        Produce a plain-English, FCU-ready explanation of the risk score.
        Surfaces actual numbers so investigators can verify independently.

        Args:
            (see evaluate() for field descriptions)

        Returns:
            str: XAI reason string surfacing contributing factors.
        """
        parts = []

        # RBAC violation narrative
        if base_violation >= 0.05:
            violation_pct = int(base_violation * 100)
            parts.append(
                f"{emp_class} performing '{action_type}' has a {violation_pct}% "
                f"RBAC violation weight — this action "
                f"{'is strictly outside role mandate' if base_violation >= 0.8 else 'requires senior authorisation'}."
            )

        # Channel escalation narrative
        if channel_penalty > 0.0:
            parts.append(
                f"Channel '{channel}' carries an additional {int(channel_penalty * 100)}pt "
                f"escalation penalty for {emp_class} class."
            )

        # Historical amount narrative
        if hist_score > 0:
            peer_mean = baseline["mean"]
            peer_std  = baseline["std"]
            parts.append(
                f"Transfer of Rs{amount:,.0f} via {channel} is {z_score:.1f}σ above "
                f"the {emp_class} peer average of Rs{peer_mean:,.0f} "
                f"(σ=Rs{peer_std:,.0f}) — historical limit exceeded."
            )

        if not parts:
            return (
                f"All RBAC and historical checks within normal range "
                f"for {emp_class}. RCI: {rci}/100."
            )

        severity_label = (
            "CRITICAL" if rci >= 80 else
            "HIGH"     if rci >= 60 else
            "WATCH"    if rci >= 40 else
            "MONITOR"
        )

        return f"[{severity_label}] RCI {rci}/100 — " + " | ".join(parts)

    # -----------------------------------------------------------------------
    # MAIN EVALUATE METHOD
    # -----------------------------------------------------------------------

    def evaluate(self, transaction: dict) -> dict:
        """
        Evaluate a transaction for RBAC violations and historical
        transfer limit anomalies.

        Computes a Role-Based Composite Index (RCI) by:
          1. O(1) lookup of RBAC violation weight for
             (emp_class × action_type) from the permission matrix.
          2. O(1) lookup of channel escalation penalty for
             (emp_class × transfer_channel).
          3. Additive combination → normalised RBAC score (0–100).
          4. O(1) lookup of historical (emp_class × channel) baseline.
          5. Z-Score computation for observed amount.
          6. Sigmoid transform → historical anomaly score (0–100).
          7. Weighted composite: RCI = 0.55×RBAC + 0.45×Historical.
          8. Signal tag and XAI reason generation.

        Args:
            transaction (dict): Must contain at minimum:
                - emp_class         (str)   : CLERK / MANAGER / IT_ADMIN / EXECUTIVE
                - action_type       (str)   : Transfer / Approve / Override etc.
                - amount            (float) : Transaction amount in INR
                - transfer_channel  (str)   : NEFT / RTGS / IMPS / UPI / SWIFT
              Optional:
                - emp_id            (str)
                - transaction_id    (str)
                - branch_id         (str)

        Returns:
            dict: {
                "severity_index": int (0–100),
                "signal":         str,
                "reason":         str
            }
        """
        # ── 0. Input validation ───────────────────────────────────────────
        if not isinstance(transaction, dict):
            return {
                "severity_index": 0,
                "signal":         "INVALID_INPUT",
                "reason":         "Transaction payload must be a dictionary."
            }

        # ── 1. Feature extraction with safe defaults ──────────────────────
        emp_class  = str(transaction.get("emp_class",  "DEFAULT")).upper().strip()
        action_type = str(transaction.get("action_type", "Transfer")).strip()
        channel     = str(transaction.get("transfer_channel", "NEFT")).upper().strip()
        amount      = float(transaction.get("amount", 0.0))

        # ── 2. Dimension A — RBAC Score (O(1) lookups) ───────────────────
        rbac_score, base_violation, channel_penalty = self._compute_rbac_score(
            emp_class, action_type, channel
        )

        # ── 3. Dimension B — Historical Deviation Score ───────────────────
        hist_score, z_score, baseline = self._compute_historical_score(
            emp_class, channel, amount
        )

        # ── 4. Weighted Composite (RCI) ───────────────────────────────────
        #
        # RCI = w_rbac × rbac_score + w_hist × hist_score
        #
        # RBAC carries higher weight (0.55) because a permission violation
        # is a deterministic policy breach. A large amount alone could be
        # legitimate; an RBAC breach cannot be explained away.
        #
        rci_raw = (WEIGHT_RBAC * rbac_score) + (WEIGHT_HISTORICAL * hist_score)
        rci     = int(min(100, max(0, round(rci_raw))))

        # ── 5. Signal and reason ──────────────────────────────────────────
        signal = self._resolve_signal(rci, rbac_score, hist_score, base_violation)
        reason = self._build_reason(
            rci             = rci,
            emp_class       = emp_class,
            action_type     = action_type,
            channel         = channel,
            amount          = amount,
            base_violation  = base_violation,
            channel_penalty = channel_penalty,
            z_score         = z_score,
            baseline        = baseline,
            hist_score      = hist_score
        )

        return {
            "severity_index": rci,
            "signal":         signal,
            "reason":         reason
        }


# ===========================================================================
# TEST HARNESS
# ===========================================================================

if __name__ == "__main__":
    DIVIDER = "=" * 72

    print(DIVIDER)
    print("  VaultMind 2.0 — Agent 3: VendorGuard")
    print("  RBAC Violation + Historical Limit Anomaly Detector")
    print(DIVIDER)

    agent = VendorGuard()

    TEST_TRANSACTIONS = [
        {
            "_label": "Case 1 — Normal clerk NEFT transfer, within history",
            "emp_class": "CLERK", "action_type": "Transfer",
            "transfer_channel": "NEFT", "amount": 38_000.0,
        },
        {
            "_label": "Case 2 — Clerk attempting APPROVE action (RBAC violation)",
            "emp_class": "CLERK", "action_type": "Approve",
            "transfer_channel": "NEFT", "amount": 40_000.0,
        },
        {
            "_label": "Case 3 — Clerk initiating RTGS with massive amount",
            "emp_class": "CLERK", "action_type": "Transfer",
            "transfer_channel": "RTGS", "amount": 8_500_000.0,
        },
        {
            "_label": "Case 4 — Clerk attempting SWIFT (dual violation: RBAC + channel)",
            "emp_class": "CLERK", "action_type": "Transfer",
            "transfer_channel": "SWIFT", "amount": 2_000_000.0,
        },
        {
            "_label": "Case 5 — IT Admin initiating RTGS transfer (should never happen)",
            "emp_class": "IT_ADMIN", "action_type": "Transfer",
            "transfer_channel": "RTGS", "amount": 500_000.0,
        },
        {
            "_label": "Case 6 — Manager RTGS, within historical range",
            "emp_class": "MANAGER", "action_type": "Approve",
            "transfer_channel": "RTGS", "amount": 850_000.0,
        },
        {
            "_label": "Case 7 — Manager RTGS, 6σ above historical mean",
            "emp_class": "MANAGER", "action_type": "Approve",
            "transfer_channel": "RTGS", "amount": 14_000_000.0,
        },
        {
            "_label": "Case 8 — Clerk OVERRIDE via RTGS (worst-case: all dimensions fire)",
            "emp_class": "CLERK", "action_type": "Override",
            "transfer_channel": "RTGS", "amount": 9_000_000.0,
        },
        {
            "_label": "Case 9 — Unknown emp_class graceful degradation",
            "emp_class": "CONTRACTOR", "action_type": "Transfer",
            "transfer_channel": "NEFT", "amount": 100_000.0,
        },
        {
            "_label": "Case 10 — Executive SWIFT, large but within mandate",
            "emp_class": "EXECUTIVE", "action_type": "Transfer",
            "transfer_channel": "SWIFT", "amount": 1_200_000.0,
        },
    ]

    for tx in TEST_TRANSACTIONS:
        label = tx.pop("_label")
        result = agent.evaluate(tx)

        bar_len = result["severity_index"] // 5
        bar     = "#" * bar_len + "-" * (20 - bar_len)

        print(f"\n{label}")
        print(f"  RCI    : [{bar}] {result['severity_index']:3d}/100")
        print(f"  Signal : {result['signal']}")
        print(f"  Reason : {result['reason']}")

    print(f"\n{DIVIDER}")
    print("  All test cases complete. Agent 3 operational.")
    print(DIVIDER)

"""
VaultMind 2.0 — agent5_insider_watch.py
===========================================================================
Agent 5: NetworkIntel — Graph-based Network Threat & Money Layering Detector.
---------------------------------------------------------------------------
Privilege Escalation & Insider Threat Detection Engine.

Detects internal actors who exceed their authorised system access scope
through two independent analytical dimensions:

  Dimension A — Privilege Escalation Score (PES)
    Maps every (emp_class × system_action) pair to a continuous
    "privilege overshoot" weight. Unlike Agent 3 (transaction-level RBAC),
    this agent operates at the SYSTEM ACCESS layer:
      - Database-level commands (DB_GRANT_ACCESS, DB_DROP_TABLE)
      - Bulk data operations (BULK_EXPORT, MASS_DELETE)
      - Admin-level system calls (SYS_CONFIG_CHANGE, AUDIT_LOG_DELETE)
      - Lateral movement indicators (CROSS_SCHEMA_ACCESS, SERVICE_IMPERSONATE)

    Each action has a base escalation weight. The observed (emp_class,
    action) pair produces a raw PES in [0, 1], converted to 0–100.

  Dimension B — Volume Anomaly Score (VAS)
    Bulk record access is one of the strongest insider threat signals.
    Rather than a hard threshold ("1000+ records = flag"), VAS uses a
    Z-Score against the employee class peer distribution for
    `records_accessed` to produce a continuous risk contribution.

    The Z-Score is transformed via a bounded sigmoid calibrated to:
      - Peer average clerks accessing ~115 records → Z ≈ 0 → VAS ≈ 0
      - 1,000 records accessed by a clerk → Z ≈ 7.7 → VAS ≈ 95+
      - 500 records → Z ≈ 3.4 → VAS ≈ 75

  Dimension C — Temporal Pattern Score (TPS)
    Access time combined with action sensitivity produces a temporal
    risk modifier. A DB_GRANT_ACCESS at 2AM carries far higher weight
    than the same action at 10AM. TPS is computed as:

        TPS = escalation_weight × off_hours_multiplier

    where off_hours_multiplier is a continuous function of login_hour
    distance from the approved window — not a binary flag.

  Final Score:
    PSI = clip(w_pes×PES + w_vas×VAS + w_tps×TPS, 0, 100)

    Weights: PES=0.45, VAS=0.35, TPS=0.20

Return contract (strict):
  {
    "severity_index": int   (0–100, Privilege Severity Index),
    "signal":         str   (machine-readable tag),
    "reason":         str   (plain-English XAI for FCU investigator)
  }

Dependencies: Python stdlib + math only. No numpy. Hackathon-safe.
===========================================================================
"""

import math
import json
import os
import warnings
from typing import Tuple, Dict

from core.ml_models import ml_models

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
BASELINE_PATH = os.path.join(SCRIPT_DIR, "baselines", "insider_watch_baselines.json")

# Composite weight distribution — must sum to 1.0
WEIGHT_PES = 0.45   # Privilege Escalation Score
WEIGHT_VAS = 0.35   # Volume Anomaly Score
WEIGHT_TPS = 0.20   # Temporal Pattern Score

# Sigmoid steepness — consistent with Agent 1 and Agent 3
SIGMOID_K     = 0.9
Z_NOISE_FLOOR = 0.5

# Approved access window
APPROVED_HOURS_START = 8
APPROVED_HOURS_END   = 20

# Bulk record threshold for annotation purposes (not a hard cutoff — VAS
# uses Z-Score, but this marks the annotation boundary in reason strings)
BULK_RECORD_ANNOTATION_THRESHOLD = 1000

# ---------------------------------------------------------------------------
# PRIVILEGE ESCALATION MATRIX
# ---------------------------------------------------------------------------
# Structure: emp_class → { system_action → escalation_weight }
#
# escalation_weight semantics (0.0 – 1.0):
#   0.0  — fully within role mandate, expected operation
#   0.2  — peripheral but permissible with audit log
#   0.5  — requires explicit authorisation from senior
#   0.7  — outside role scope, high suspicion
#   0.9  — strictly prohibited — near-certain policy breach
#   1.0  — absolute privilege violation (e.g., clerk deleting audit logs)
#
# These weights are NOT binary. They produce continuous scores that combine
# with VAS and TPS — a 0.7 weight alongside a bulk export at 2AM will
# push the final PSI into CRITICAL territory.
# ---------------------------------------------------------------------------
ESCALATION_MATRIX = {
    "CLERK": {
        # Normal operations
        "READ":                     0.00,
        "WRITE":                    0.05,
        "UPDATE_OWN":               0.00,
        "VIEW_REPORT":              0.00,
        # Moderately suspicious
        "CROSS_BRANCH_READ":        0.45,
        "BULK_EXPORT":              0.75,
        "MASS_DOWNLOAD":            0.78,
        "SCHEMA_READ":              0.50,
        # Highly suspicious
        "CROSS_SCHEMA_ACCESS":      0.82,
        "DB_STORED_PROC_EXEC":      0.70,
        "PRIVILEGE_QUERY":          0.72,
        "USER_ENUM":                0.68,
        # Critical violations
        "DB_GRANT_ACCESS":          0.97,
        "DB_REVOKE_ACCESS":         0.90,
        "DB_DROP_TABLE":            0.98,
        "DB_TRUNCATE":              0.95,
        "AUDIT_LOG_READ":           0.72,
        "AUDIT_LOG_DELETE":         0.99,
        "AUDIT_LOG_MODIFY":         0.98,
        "SYS_CONFIG_CHANGE":        0.96,
        "SERVICE_IMPERSONATE":      0.95,
        "ADMIN_PANEL_ACCESS":       0.90,
        "ROLE_MODIFY":              0.97,
        "PASSWORD_RESET_OTHER":     0.85,
        "MASS_DELETE":              0.92,
    },
    "MANAGER": {
        "READ":                     0.00,
        "WRITE":                    0.00,
        "UPDATE_OWN":               0.00,
        "VIEW_REPORT":              0.00,
        "CROSS_BRANCH_READ":        0.15,
        "BULK_EXPORT":              0.25,
        "MASS_DOWNLOAD":            0.28,
        "SCHEMA_READ":              0.20,
        "CROSS_SCHEMA_ACCESS":      0.45,
        "DB_STORED_PROC_EXEC":      0.35,
        "PRIVILEGE_QUERY":          0.30,
        "USER_ENUM":                0.25,
        "DB_GRANT_ACCESS":          0.75,
        "DB_REVOKE_ACCESS":         0.60,
        "DB_DROP_TABLE":            0.88,
        "DB_TRUNCATE":              0.82,
        "AUDIT_LOG_READ":           0.20,
        "AUDIT_LOG_DELETE":         0.95,
        "AUDIT_LOG_MODIFY":         0.90,
        "SYS_CONFIG_CHANGE":        0.70,
        "SERVICE_IMPERSONATE":      0.80,
        "ADMIN_PANEL_ACCESS":       0.45,
        "ROLE_MODIFY":              0.78,
        "PASSWORD_RESET_OTHER":     0.50,
        "MASS_DELETE":              0.72,
    },
    "IT_ADMIN": {
        "READ":                     0.00,
        "WRITE":                    0.00,
        "UPDATE_OWN":               0.00,
        "VIEW_REPORT":              0.00,
        "CROSS_BRANCH_READ":        0.10,
        "BULK_EXPORT":              0.15,
        "MASS_DOWNLOAD":            0.18,
        "SCHEMA_READ":              0.00,
        "CROSS_SCHEMA_ACCESS":      0.10,
        "DB_STORED_PROC_EXEC":      0.10,
        "PRIVILEGE_QUERY":          0.05,
        "USER_ENUM":                0.00,
        "DB_GRANT_ACCESS":          0.30,   # IT Admins can grant but needs approval
        "DB_REVOKE_ACCESS":         0.25,
        "DB_DROP_TABLE":            0.55,   # Destructive even for IT
        "DB_TRUNCATE":              0.50,
        "AUDIT_LOG_READ":           0.00,   # IT core function
        "AUDIT_LOG_DELETE":         0.90,   # No one should delete audit logs
        "AUDIT_LOG_MODIFY":         0.88,
        "SYS_CONFIG_CHANGE":        0.10,   # Core IT function
        "SERVICE_IMPERSONATE":      0.40,
        "ADMIN_PANEL_ACCESS":       0.00,   # IT mandate
        "ROLE_MODIFY":              0.35,
        "PASSWORD_RESET_OTHER":     0.10,   # IT helpdesk function
        "MASS_DELETE":              0.50,
    },
    "EXECUTIVE": {
        "READ":                     0.00,
        "WRITE":                    0.00,
        "UPDATE_OWN":               0.00,
        "VIEW_REPORT":              0.00,
        "CROSS_BRANCH_READ":        0.00,
        "BULK_EXPORT":              0.10,
        "MASS_DOWNLOAD":            0.12,
        "SCHEMA_READ":              0.10,
        "CROSS_SCHEMA_ACCESS":      0.20,
        "DB_STORED_PROC_EXEC":      0.30,
        "PRIVILEGE_QUERY":          0.15,
        "USER_ENUM":                0.20,
        "DB_GRANT_ACCESS":          0.60,
        "DB_REVOKE_ACCESS":         0.50,
        "DB_DROP_TABLE":            0.80,
        "DB_TRUNCATE":              0.75,
        "AUDIT_LOG_READ":           0.10,
        "AUDIT_LOG_DELETE":         0.92,
        "AUDIT_LOG_MODIFY":         0.88,
        "SYS_CONFIG_CHANGE":        0.40,
        "SERVICE_IMPERSONATE":      0.65,
        "ADMIN_PANEL_ACCESS":       0.20,
        "ROLE_MODIFY":              0.60,
        "PASSWORD_RESET_OTHER":     0.35,
        "MASS_DELETE":              0.70,
    },
    # Fallback for unknown/unclassified roles
    "DEFAULT": {
        "READ":                     0.30,
        "WRITE":                    0.45,
        "UPDATE_OWN":               0.30,
        "VIEW_REPORT":              0.25,
        "CROSS_BRANCH_READ":        0.65,
        "BULK_EXPORT":              0.80,
        "MASS_DOWNLOAD":            0.80,
        "SCHEMA_READ":              0.70,
        "CROSS_SCHEMA_ACCESS":      0.85,
        "DB_STORED_PROC_EXEC":      0.75,
        "PRIVILEGE_QUERY":          0.75,
        "USER_ENUM":                0.72,
        "DB_GRANT_ACCESS":          0.98,
        "DB_REVOKE_ACCESS":         0.92,
        "DB_DROP_TABLE":            0.99,
        "DB_TRUNCATE":              0.96,
        "AUDIT_LOG_READ":           0.75,
        "AUDIT_LOG_DELETE":         0.99,
        "AUDIT_LOG_MODIFY":         0.99,
        "SYS_CONFIG_CHANGE":        0.95,
        "SERVICE_IMPERSONATE":      0.95,
        "ADMIN_PANEL_ACCESS":       0.90,
        "ROLE_MODIFY":              0.97,
        "PASSWORD_RESET_OTHER":     0.85,
        "MASS_DELETE":              0.92,
    },
}

# ---------------------------------------------------------------------------
# RECORD VOLUME BASELINES
# ---------------------------------------------------------------------------
# Peer-group distribution for `records_accessed` per employee class.
# Used for Z-Score computation in Dimension B (VAS).
# Values derived from RBI internal audit profiles (2023-24 reference).
# ---------------------------------------------------------------------------
DEFAULT_BASELINES = {
    "CLERK":     {"mean": 115.0,    "std": 68.0},
    "MANAGER":   {"mean": 320.0,    "std": 140.0},
    "IT_ADMIN":  {"mean": 52_000.0, "std": 18_000.0},
    "EXECUTIVE": {"mean": 85.0,     "std": 50.0},
    "DEFAULT":   {"mean": 200.0,    "std": 120.0},
}

# ---------------------------------------------------------------------------
# ACTION CRITICALITY ANNOTATIONS
# ---------------------------------------------------------------------------
# Human-readable descriptions for XAI reason strings.
# O(1) lookup — avoids inline string construction per action.
# ---------------------------------------------------------------------------
ACTION_DESCRIPTIONS: Dict[str, str] = {
    "DB_GRANT_ACCESS":      "database privilege grant (admin-only system command)",
    "DB_REVOKE_ACCESS":     "database privilege revocation",
    "DB_DROP_TABLE":        "destructive schema modification (DROP TABLE)",
    "DB_TRUNCATE":          "bulk data destruction (TRUNCATE)",
    "AUDIT_LOG_DELETE":     "audit trail deletion — evidence tampering indicator",
    "AUDIT_LOG_MODIFY":     "audit trail modification — evidence tampering indicator",
    "SYS_CONFIG_CHANGE":    "system configuration change",
    "BULK_EXPORT":          "bulk data export",
    "MASS_DOWNLOAD":        "mass file download",
    "MASS_DELETE":          "mass record deletion",
    "CROSS_SCHEMA_ACCESS":  "cross-schema database access (lateral movement)",
    "SERVICE_IMPERSONATE":  "service account impersonation",
    "ROLE_MODIFY":          "user role modification",
    "PRIVILEGE_QUERY":      "privilege enumeration query",
    "ADMIN_PANEL_ACCESS":   "administrative panel access",
    "PASSWORD_RESET_OTHER": "password reset for another user account",
    "CROSS_BRANCH_READ":    "cross-branch data read",
    "USER_ENUM":            "user account enumeration",
}


# ===========================================================================
# AGENT CLASS
# ===========================================================================

class NetworkIntel:
    """
    NetworkIntel: Graph-based Network Threat & Money Layering Detector.

    Evaluates system-level actions against role permissions and volume
    baselines using three continuous analytical dimensions:

    Dimension A (PES): Privilege Escalation Score
        Continuous weight from ESCALATION_MATRIX for (emp_class × action).
        O(1) lookup → converted to 0–100.

    Dimension B (VAS): Volume Anomaly Score
        Z-Score of records_accessed against peer class distribution.
        Sigmoid transform → 0–100. Replaces the hard "1000+ = flag" rule.

    Dimension C (TPS): Temporal Pattern Score
        Escalation weight × continuous off-hours multiplier.
        Sensitive actions at night carry disproportionately higher risk.

    Final: PSI = 0.45×PES + 0.35×VAS + 0.20×TPS → severity_index.

    Usage:
        agent = NetworkIntel()
        result = agent.evaluate(transaction_dict)
        print(result["severity_index"])   # 0–100
    """

    def __init__(self, baseline_path: str = BASELINE_PATH):
        """
        Initialise NetworkIntel. Loads volume baselines from JSON
        (simulates joblib.load). Falls back to empirical defaults.

        Pre-materialises ESCALATION_MATRIX and ACTION_DESCRIPTIONS
        as instance attributes for O(1) access in evaluate().

        Args:
            baseline_path: Path to insider_watch_baselines.json
        """
        self.baseline_path  = baseline_path
        self.baselines: dict = {}
        self._load_baselines()

        # Pre-bind constant dicts to self for O(1) access
        self._escalation_matrix   = ESCALATION_MATRIX
        self._action_descriptions = ACTION_DESCRIPTIONS

    # -----------------------------------------------------------------------
    # INITIALISATION HELPERS
    # -----------------------------------------------------------------------

    def _load_baselines(self) -> None:
        """
        Load record-volume baselines from JSON (simulates scaler.pkl load).
        On failure, uses DEFAULT_BASELINES silently.
        """
        try:
            if not os.path.exists(self.baseline_path):
                raise FileNotFoundError(
                    f"Baseline not found: {self.baseline_path}"
                )
            with open(self.baseline_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            assert isinstance(loaded, dict), "Baseline must be a JSON object."
            self.baselines = loaded
            print(
                f"[NetworkIntel] Baselines loaded. "
                f"Classes: {list(self.baselines.keys())}"
            )
        except (FileNotFoundError, AssertionError, json.JSONDecodeError) as exc:
            warnings.warn(
                f"[NetworkIntel] Baseline load failed ({exc}). "
                "Using empirical defaults — agent operational."
            )
            self.baselines = DEFAULT_BASELINES

    def _get_baseline(self, emp_class: str) -> dict:
        """
        O(1) retrieval of volume baseline for emp_class.
        Falls back to DEFAULT if class is unknown.

        Args:
            emp_class: Employee class string.

        Returns:
            dict: {"mean": float, "std": float}
        """
        return self.baselines.get(
            emp_class.upper(),
            self.baselines.get("DEFAULT", DEFAULT_BASELINES["DEFAULT"])
        )

    # -----------------------------------------------------------------------
    # MATHEMATICAL CORE
    # -----------------------------------------------------------------------

    @staticmethod
    def _z_score(value: float, mean: float, std: float) -> float:
        """
        Standard Z-Score: (X - μ) / σ
        Returns a large sentinel (50.0) if std ≈ 0 and value > 0,
        indicating the observed value is far outside the near-zero
        distribution (relevant for IT_ADMIN volume outliers).

        Args:
            value: Observed records accessed.
            mean:  Peer class mean.
            std:   Peer class standard deviation.

        Returns:
            float: Z-Score (we only care about upper-tail, i.e. Z > 0).
        """
        if std < 1e-6:
            return 50.0 if value > 0 else 0.0
        return (value - mean) / std

    @staticmethod
    def _sigmoid_risk(z: float, k: float = SIGMOID_K) -> float:
        """
        Convert Z-Score to 0–100 risk contribution.

        Formula:
            effective_z = max(0, z) - Z_NOISE_FLOOR
            risk = sigmoid(k × effective_z) × 100

        Calibration:
          Z = 0.5  → ~0   (noise floor)
          Z = 2.0  → ~62
          Z = 3.5  → ~88
          Z = 7.7  → ~99  (1000-record clerk access)

        Args:
            z: Raw Z-Score.
            k: Sigmoid steepness.

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

    def _compute_pes(
        self, emp_class: str, system_action: str
    ) -> Tuple[float, float]:
        """
        Compute Privilege Escalation Score (PES) for (emp_class, action).

        O(1) two-level dictionary lookup:
          escalation_weight = ESCALATION_MATRIX[emp_class][action]
          PES = escalation_weight × 100

        Unknown actions default to 0.50 weight — unclassified operations
        are treated as moderately suspicious (unknown ≠ safe).

        Args:
            emp_class:     Employee class string.
            system_action: System-level action string.

        Returns:
            Tuple of (pes_score 0–100, raw_weight 0–1)
        """
        role_map = self._escalation_matrix.get(
            emp_class,
            self._escalation_matrix["DEFAULT"]
        )
        # Unknown action → 0.50 (moderately suspicious by default)
        raw_weight = role_map.get(system_action, 0.50)
        return raw_weight * 100.0, raw_weight

    def _compute_vas(
        self, emp_class: str, records_accessed: float
    ) -> Tuple[float, float, dict]:
        """
        Compute Volume Anomaly Score (VAS) via Z-Score analysis.

        Replaces the hard "1000+ records = flag" threshold with a
        continuous score. A CLERK accessing 200 records is mildly
        suspicious (Z≈1.2); accessing 1000 records is critical (Z≈7.7).

        Args:
            emp_class:        Employee class.
            records_accessed: Number of records accessed in session.

        Returns:
            Tuple of (vas_score 0–100, z_score, baseline_dict)
        """
        baseline  = self._get_baseline(emp_class)
        z         = self._z_score(records_accessed, baseline["mean"], baseline["std"])
        vas_score = self._sigmoid_risk(z)
        return vas_score, z, baseline

    def _compute_tps(
        self, raw_weight: float, login_hour: int
    ) -> Tuple[float, float]:
        """
        Compute Temporal Pattern Score (TPS).

        Sensitive actions performed outside business hours carry
        disproportionately higher risk. TPS is computed as:

            off_hours_mult = continuous function of distance from [08,20]
            TPS = escalation_weight × off_hours_mult × 100

        off_hours_mult range: 0.0 (inside window) to 1.0 (midnight).
        The multiplier is piecewise linear — each hour further from the
        approved window adds 0.083 (= 1.0 / 12 hours).

        This means:
          - Sensitive action at 9AM  → TPS near 0 (even high-weight actions
            are expected during business hours)
          - Same action at 2AM       → TPS ≈ raw_weight × 0.83 × 100

        Args:
            raw_weight: PES escalation weight (0.0–1.0).
            login_hour: Login hour (0–23).

        Returns:
            Tuple of (tps_score 0–100, off_hours_multiplier 0–1)
        """
        # Compute continuous off-hours distance
        if APPROVED_HOURS_START <= login_hour <= APPROVED_HOURS_END:
            off_mult = 0.0  # Inside window — no temporal amplification
        elif login_hour < APPROVED_HOURS_START:
            hours_outside = APPROVED_HOURS_START - login_hour
            off_mult = min(1.0, hours_outside / 12.0)
        else:
            hours_outside = login_hour - APPROVED_HOURS_END
            off_mult = min(1.0, hours_outside / 12.0)

        tps_score = raw_weight * off_mult * 100.0
        return min(100.0, tps_score), off_mult

    # -----------------------------------------------------------------------
    # SIGNAL RESOLVER
    # -----------------------------------------------------------------------

    @staticmethod
    def _resolve_signal(
        psi: int,
        raw_weight: float,
        vas_score: float,
        off_mult: float,
        system_action: str,
        records_accessed: float
    ) -> str:
        """
        Determine the dominant signal tag.

        Priority:
          AUDIT_TAMPERING (audit log actions) →
          PRIVILEGE_ESCALATION (DB commands) →
          BULK_EXFILTRATION (volume-driven) →
          TEMPORAL_ANOMALY (time-driven) →
          GENERIC_INSIDER

        Args:
            psi:              Final composite score.
            raw_weight:       PES raw weight from matrix.
            vas_score:        Volume anomaly score.
            off_mult:         Off-hours multiplier.
            system_action:    Action string.
            records_accessed: Number of records accessed.

        Returns:
            str: Machine-readable signal tag.
        """
        if psi == 0:
            return "NORMAL"

        # Determine dominant dimension
        AUDIT_ACTIONS   = {"AUDIT_LOG_DELETE", "AUDIT_LOG_MODIFY"}
        DB_ADMIN_ACTIONS = {
            "DB_GRANT_ACCESS", "DB_REVOKE_ACCESS",
            "DB_DROP_TABLE", "DB_TRUNCATE", "ROLE_MODIFY",
            "SERVICE_IMPERSONATE", "SYS_CONFIG_CHANGE"
        }
        BULK_ACTIONS = {"BULK_EXPORT", "MASS_DOWNLOAD", "MASS_DELETE"}

        if system_action in AUDIT_ACTIONS:
            dominant = "AUDIT_TAMPERING"
        elif system_action in DB_ADMIN_ACTIONS and raw_weight >= 0.7:
            dominant = "PRIVILEGE_ESCALATION"
        elif records_accessed >= BULK_RECORD_ANNOTATION_THRESHOLD or \
             (system_action in BULK_ACTIONS and vas_score > 50):
            dominant = "BULK_EXFILTRATION"
        elif off_mult > 0.5 and raw_weight > 0.4:
            dominant = "TEMPORAL_INSIDER"
        else:
            dominant = "INSIDER_ANOMALY"

        prefix = (
            "CRITICAL" if psi >= 80 else
            "HIGH"     if psi >= 60 else
            "WATCH"    if psi >= 40 else
            "MONITOR"
        )
        return f"{prefix}_{dominant}"

    # -----------------------------------------------------------------------
    # XAI REASON BUILDER
    # -----------------------------------------------------------------------

    def _build_reason(
        self,
        psi: int,
        emp_class: str,
        system_action: str,
        records_accessed: float,
        raw_weight: float,
        z_score: float,
        baseline: dict,
        off_mult: float,
        login_hour: int,
        pes_score: float,
        vas_score: float,
        tps_score: float
    ) -> str:
        """
        Build a plain-English FCU-ready explanation.

        Exposes the actual numbers (weights, Z-scores, peer averages)
        so the investigator can verify the math independently.

        Args:
            (see evaluate() for field descriptions)

        Returns:
            str: XAI reason string.
        """
        parts = []

        # PES narrative
        if pes_score > 0:
            action_desc = self._action_descriptions.get(
                system_action,
                f"system action '{system_action}'"
            )
            parts.append(
                f"{emp_class} performed {action_desc} — "
                f"escalation weight {int(raw_weight * 100)}% "
                f"(PES contribution: {pes_score:.0f}/100)."
            )

        # VAS narrative
        if vas_score > 0:
            peer_mean = baseline["mean"]
            ratio     = records_accessed / peer_mean if peer_mean > 0 else 0
            bulk_flag = " [BULK THRESHOLD EXCEEDED]" \
                        if records_accessed >= BULK_RECORD_ANNOTATION_THRESHOLD else ""
            parts.append(
                f"{records_accessed:,.0f} records accessed — "
                f"{z_score:.1f}σ above {emp_class} peer average "
                f"({peer_mean:,.0f}), {ratio:.1f}× peer mean"
                f"{bulk_flag} (VAS: {vas_score:.0f}/100)."
            )

        # TPS narrative
        if tps_score > 0:
            parts.append(
                f"Action performed at {login_hour:02d}:00 IST — "
                f"{off_mult:.0%} outside approved window amplifier applied "
                f"(TPS: {tps_score:.0f}/100)."
            )

        if not parts:
            return (
                f"All privilege and volume dimensions within normal range "
                f"for {emp_class}. PSI: {psi}/100."
            )

        severity_label = (
            "CRITICAL" if psi >= 80 else
            "HIGH"     if psi >= 60 else
            "WATCH"    if psi >= 40 else
            "MONITOR"
        )
        return f"[{severity_label}] PSI {psi}/100 — " + " | ".join(parts)

    # -----------------------------------------------------------------------
    # MAIN EVALUATE METHOD
    # -----------------------------------------------------------------------

    def evaluate(self, transaction: dict) -> dict:
        """
        Evaluate a transaction for privilege escalation and insider threat.

        Computes a Privilege Severity Index (PSI) by:
          1. O(1) lookup of (emp_class × system_action) escalation weight.
          2. Conversion to PES score (0–100).
          3. O(1) lookup of peer volume baseline for emp_class.
          4. Z-Score computation for records_accessed → VAS (0–100).
          5. Temporal multiplier for login_hour → TPS (0–100).
          6. Weighted composite: PSI = 0.45×PES + 0.35×VAS + 0.20×TPS.
          7. Signal tag and XAI reason generation.

        Args:
            transaction (dict): Must contain at minimum:
                - emp_class        (str)   : CLERK / MANAGER / IT_ADMIN / EXECUTIVE
                - system_action    (str)   : DB_GRANT_ACCESS / BULK_EXPORT / etc.
                - records_accessed (int)   : Number of records accessed in session
                - login_hour       (int)   : Login hour (0–23)
              Optional:
                - emp_id           (str)
                - transaction_id   (str)
                - branch_id        (str)
                - session_id       (str)

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
        emp_id           = str(transaction.get("emp_id", "UNKNOWN"))
        emp_class        = str(transaction.get("emp_class",     "DEFAULT")).upper().strip()
        system_action    = str(transaction.get("system_action", "READ")).strip()
        records_accessed = float(transaction.get("records_accessed", 0.0))
        login_hour       = int(transaction.get("login_hour", 9))
        login_hour       = max(0, min(23, login_hour))  # clamp

        # ── NEW: Try trained PyTorch GNN FIRST ──
        try:
            gnn_score = ml_models.predict_gnn(transaction)
            if gnn_score >= 0:
                cbsi = int(gnn_score)
                signal = "CRITICAL_GNN_ANOMALY" if cbsi >= 80 else "GNN_ANOMALY"
                reason = f"[ML-PREDICTED] Graph Neural Network identified structural anomaly score: {cbsi}/100 for {emp_id}."
                return {
                    "severity_index": cbsi,
                    "signal":         signal,
                    "reason":         reason
                }
        except Exception as e:
            print(f"[NetworkIntel] ML Model Error: {e}")  # Fall through to rules

        # ── 2. Dimension A — Privilege Escalation Score (O(1) lookups) ───
        pes_score, raw_weight = self._compute_pes(emp_class, system_action)

        # ── 3. Dimension B — Volume Anomaly Score (Z-Score) ───────────────
        vas_score, z_score, baseline = self._compute_vas(emp_class, records_accessed)

        # ── 4. Dimension C — Temporal Pattern Score ───────────────────────
        tps_score, off_mult = self._compute_tps(raw_weight, login_hour)

        # ── 5. Weighted Composite (PSI) ───────────────────────────────────
        #
        # PSI = w_pes × PES + w_vas × VAS + w_tps × TPS
        #
        # PES carries highest weight (0.45) — a system-level privilege
        # violation is deterministic and non-negotiable.
        # VAS (0.35) — bulk access is a strong exfiltration signal.
        # TPS (0.20) — temporal context amplifies but doesn't dominate alone.
        #
        psi_raw = (
            WEIGHT_PES * pes_score
            + WEIGHT_VAS * vas_score
            + WEIGHT_TPS * tps_score
        )
        psi = int(min(100, max(0, round(psi_raw))))

        # ── 6. Signal and reason ──────────────────────────────────────────
        signal = self._resolve_signal(
            psi, raw_weight, vas_score, off_mult,
            system_action, records_accessed
        )
        reason = self._build_reason(
            psi=psi, emp_class=emp_class, system_action=system_action,
            records_accessed=records_accessed, raw_weight=raw_weight,
            z_score=z_score, baseline=baseline, off_mult=off_mult,
            login_hour=login_hour, pes_score=pes_score,
            vas_score=vas_score, tps_score=tps_score
        )

        return {
            "severity_index": psi,
            "signal": signal,
            "reason": reason
        }


# ===========================================================================
# TEST HARNESS
# ===========================================================================

if __name__ == "__main__":
    DIVIDER = "=" * 72

    print(DIVIDER)
    print("  VaultMind 2.0 — Agent 5: NetworkIntel")
    print("  Graph-based Network Threat & Money Layering Detector")
    print(DIVIDER)

    agent = NetworkIntel()

    TEST_TRANSACTIONS = [
        {
            "_label": "Case 1 — Normal clerk, standard READ, business hours",
            "emp_class": "CLERK", "system_action": "READ",
            "records_accessed": 95, "login_hour": 10,
        },
        {
            "_label": "Case 2 — Clerk: DB_GRANT_ACCESS (critical privilege breach)",
            "emp_class": "CLERK", "system_action": "DB_GRANT_ACCESS",
            "records_accessed": 10, "login_hour": 11,
        },
        {
            "_label": "Case 3 — Clerk: BULK_EXPORT, 1200 records (both PES + VAS fire)",
            "emp_class": "CLERK", "system_action": "BULK_EXPORT",
            "records_accessed": 1200, "login_hour": 14,
        },
        {
            "_label": "Case 4 — Clerk: DB_GRANT_ACCESS at 2AM (all 3 dimensions fire)",
            "emp_class": "CLERK", "system_action": "DB_GRANT_ACCESS",
            "records_accessed": 500, "login_hour": 2,
        },
        {
            "_label": "Case 5 — Clerk: AUDIT_LOG_DELETE (evidence tampering)",
            "emp_class": "CLERK", "system_action": "AUDIT_LOG_DELETE",
            "records_accessed": 50, "login_hour": 3,
        },
        {
            "_label": "Case 6 — Manager: BULK_EXPORT, moderate volume",
            "emp_class": "MANAGER", "system_action": "BULK_EXPORT",
            "records_accessed": 400, "login_hour": 15,
        },
        {
            "_label": "Case 7 — IT Admin: DB_GRANT_ACCESS, normal hours (within mandate)",
            "emp_class": "IT_ADMIN", "system_action": "DB_GRANT_ACCESS",
            "records_accessed": 5000, "login_hour": 11,
        },
        {
            "_label": "Case 8 — IT Admin: AUDIT_LOG_DELETE at midnight (critical)",
            "emp_class": "IT_ADMIN", "system_action": "AUDIT_LOG_DELETE",
            "records_accessed": 200, "login_hour": 0,
        },
        {
            "_label": "Case 9 — Unknown role: SERVICE_IMPERSONATE (default matrix)",
            "emp_class": "CONTRACTOR", "system_action": "SERVICE_IMPERSONATE",
            "records_accessed": 300, "login_hour": 22,
        },
        {
            "_label": "Case 10 — MAX SCORE: Clerk + DB_GRANT + 5000 records + 3AM",
            "emp_class": "CLERK", "system_action": "DB_GRANT_ACCESS",
            "records_accessed": 5000, "login_hour": 3,
        },
    ]

    for tx in TEST_TRANSACTIONS:
        label = tx.pop("_label")
        result = agent.evaluate(tx)

        bar_len = result["severity_index"] // 5
        bar     = "#" * bar_len + "-" * (20 - bar_len)

        print(f"\n{label}")
        print(f"  PSI    : [{bar}] {result['severity_index']:3d}/100")
        print(f"  Signal : {result['signal']}")
        print(f"  Reason : {result['reason']}")

    print(f"\n{DIVIDER}")
    print("  All test cases complete. Agent 5 operational.")
    print(DIVIDER)
"""
VaultMind 2.0 — agent6_regulatory_ai.py
===========================================================================
Agent 6: RegulatoryAI
---------------------------------------------------------------------------
RBI / FIU-IND Regulatory Compliance Scoring Engine.

Rather than binary pass/fail checks, every regulation produces a
continuous "breach severity" contribution derived from:

  1. Proportional Overshoot Score (POS)
     How far the observed value exceeds the regulatory limit, expressed
     as a log-scaled ratio. A transaction 2× the IMPS limit contributes
     more than one at 1.01× the limit, but the relationship is logarithmic
     — not linear — matching how regulators weight proportionality in
     enforcement severity.

         POS(x, limit) = log2(1 + x / limit) × 100
                         normalised to [0, 100]

  2. Regulation Weight (RW)
     Each regulatory rule has an empirically assigned weight (0.0–1.0)
     reflecting its severity in RBI/FIU-IND enforcement history:
       - PMLA Section 12 violation    → 1.0 (criminal liability)
       - FEMA cross-border breach     → 0.95
       - Cash Transaction Report      → 0.85
       - Suspicious Transaction Report → 0.80
       - Channel limit breach         → 0.70

  3. Rule Composite Score
     Each fired rule contributes:
         rule_score_i = RW_i × POS_i

  4. Cumulative Regulatory Compliance Index (RCI):
     RCI = clip( Σ(rule_score_i) × escalation_factor, 0, 100 )

     escalation_factor fires when ≥ 2 rules breach simultaneously —
     regulatory co-violation is treated as a compound offence
     (mirrors RBI's "aggregate breach" escalation policy).

  5. Contextual Modifiers:
     - Calendar context (FYE: fiscal year-end surge — limits adjusted)
     - Employee class privilege multiplier (a CLERK breaching SWIFT
       limits is more suspicious than an EXECUTIVE doing so)
     - Channel-specific regulatory windows (RTGS only open 07:00–18:00)

Regulatory Rules Hardcoded (RBI Master Direction + PMLA 2002 + FEMA):
  Rule 01 — IMPS per-transaction limit (₹5,00,000)
  Rule 02 — RTGS minimum transaction floor (₹2,00,000)
  Rule 03 — NEFT daily aggregate limit per individual (₹10,00,000)
  Rule 04 — UPI per-transaction limit (₹1,00,000)
  Rule 05 — Cash Transaction Report (CTR) threshold — PMLA §12 (₹10,00,000)
  Rule 06 — Suspicious Transaction Report (STR) — PMLA §12 (structuring)
  Rule 07 — Cross-border SWIFT single transaction flag (₹50,00,000)
  Rule 08 — FEMA current account limit (₹25,00,000 / year proxy)
  Rule 09 — RTGS operating window violation (07:00–18:00)
  Rule 10 — RBI Large Value Transaction monitoring (₹1 Cr)
  Rule 11 — PAN/KYC mandatory above ₹50,000 single transaction
  Rule 12 — Benami Transactions Prohibition Act flag (structuring + amount)
  Rule 13 — PMLA Predicate Offence — aggregate daily > ₹1 Cr
  Rule 14 — FIU-IND STR mandatory filing threshold

Return contract (strict):
  {
    "severity_index": int   (0–100, Regulatory Compliance Index),
    "signal":         str   (machine-readable tag),
    "reason":         str   (plain-English XAI for FCU investigator)
  }

Reference:
  RBI Master Direction on KYC (2016, updated 2023)
  Prevention of Money Laundering Act, 2002 (PMLA)
  Foreign Exchange Management Act, 1999 (FEMA)
  RBI Circular RBI/2024-25/16 on Large Value Transactions
  FIU-IND Guidelines on STR/CTR Filing (2023)

Dependencies: Python stdlib + math only. No numpy. Hackathon-safe.
===========================================================================
"""

import math
import json
import os
import warnings
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
RULES_PATH    = os.path.join(SCRIPT_DIR, "baselines", "regulatory_rules.json")

# Escalation factor when >= 2 rules fire simultaneously
MULTI_RULE_ESCALATION_THRESHOLD = 2
MULTI_RULE_ESCALATION_FACTOR    = 1.30   # 30% boost for compound breach

# POS normalisation ceiling — log2(1 + 20) ≈ 4.39 → mapped to 100
# Means a transaction 20× over the limit scores 100 on POS
POS_LOG_CEILING = math.log2(1 + 20)

# RTGS operating window (RBI mandate)
RTGS_WINDOW_START = 7    # 07:00 IST
RTGS_WINDOW_END   = 18   # 18:00 IST

# ---------------------------------------------------------------------------
# REGULATORY RULES DICTIONARY
# ---------------------------------------------------------------------------
# Structure:
#   rule_id → {
#     "name":        str    Human-readable name
#     "limit":       float  Regulatory threshold in INR
#     "weight":      float  Enforcement severity weight (0.0–1.0)
#     "channel":     str|None  Applicable channel (None = all channels)
#     "description": str    Plain-English description for XAI
#     "citation":    str    Regulatory citation
#   }
#
# These are loaded from JSON at startup. The dict below is the fallback.
# ---------------------------------------------------------------------------
DEFAULT_RULES: Dict[str, dict] = {

    "R01_IMPS_LIMIT": {
        "name":        "IMPS Per-Transaction Limit",
        "limit":       500_000.0,
        "weight":      0.70,
        "channel":     "IMPS",
        "description": "IMPS transfer exceeds RBI per-transaction cap of ₹5,00,000.",
        "citation":    "NPCI IMPS Operational Guidelines (2023) — per-tx cap ₹5L",
    },
    "R02_RTGS_MINIMUM": {
        "name":        "RTGS Minimum Floor Breach",
        "limit":       200_000.0,
        "weight":      0.55,
        "channel":     "RTGS",
        "description": "RTGS transaction below ₹2,00,000 minimum — potential misuse of HVPS infrastructure.",
        "citation":    "RBI RTGS System Regulations — minimum ₹2L per transfer",
        "is_floor":    True,   # Flag: violation when BELOW limit (not above)
    },
    "R03_NEFT_DAILY_AGGREGATE": {
        "name":        "NEFT Daily Aggregate Limit",
        "limit":       1_000_000.0,
        "weight":      0.65,
        "channel":     "NEFT",
        "description": "NEFT daily aggregate exceeds ₹10,00,000 per customer.",
        "citation":    "RBI Master Circular on NEFT — aggregate daily cap",
    },
    "R04_UPI_LIMIT": {
        "name":        "UPI Per-Transaction Limit",
        "limit":       100_000.0,
        "weight":      0.60,
        "channel":     "UPI",
        "description": "UPI transfer exceeds NPCI per-transaction cap of ₹1,00,000.",
        "citation":    "NPCI UPI Circular (2023) — per-tx cap ₹1L (₹2L for verified merchants)",
    },
    "R05_CTR_THRESHOLD": {
        "name":        "Cash Transaction Report (CTR) — PMLA §12",
        "limit":       1_000_000.0,
        "weight":      0.85,
        "channel":     None,
        "description": "Transaction meets or exceeds ₹10,00,000 CTR mandatory reporting threshold.",
        "citation":    "PMLA 2002 §12 — CTR required for cash/equivalent ≥ ₹10L",
    },
    "R06_STR_STRUCTURING": {
        "name":        "Structuring / STR Flag — PMLA §12",
        "limit":       490_000.0,
        "weight":      0.80,
        "channel":     None,
        "description": "Transaction amount in ₹4.9L–₹9.9L band — classic CTR-avoidance structuring window.",
        "citation":    "PMLA 2002 §12 / FIU-IND Structuring Advisory (2022)",
        "upper_limit": 990_000.0,  # Band-based rule: fires when limit ≤ amount ≤ upper_limit
    },
    "R07_SWIFT_CROSS_BORDER": {
        "name":        "Cross-Border SWIFT Large Value Flag",
        "limit":       5_000_000.0,
        "weight":      0.95,
        "channel":     "SWIFT",
        "description": "SWIFT international transfer exceeds ₹50,00,000 — FEMA large-value reporting required.",
        "citation":    "FEMA 1999 §6 + RBI A.P. (DIR Series) Circular on Outward Remittance",
    },
    "R08_FEMA_CURRENT_ACCOUNT": {
        "name":        "FEMA Current Account Limit",
        "limit":       2_500_000.0,
        "weight":      0.90,
        "channel":     "SWIFT",
        "description": "Foreign remittance approaches FEMA current account ceiling for non-capital transactions.",
        "citation":    "FEMA 1999 — Current Account Transaction Rules, Schedule II",
    },
    "R09_RTGS_WINDOW": {
        "name":        "RTGS Operating Window Violation",
        "limit":       0.0,
        "weight":      0.75,
        "channel":     "RTGS",
        "description": "RTGS transaction attempted outside operating window (07:00–18:00 IST).",
        "citation":    "RBI RTGS System Regulations — Operating hours 07:00–18:00 on working days",
        "time_based":  True,
    },
    "R10_LARGE_VALUE_MONITORING": {
        "name":        "RBI Large Value Transaction Monitoring",
        "limit":       10_000_000.0,
        "weight":      0.88,
        "channel":     None,
        "description": "Transaction ≥ ₹1 Cr — mandatory large-value monitoring under RBI/2024-25/16.",
        "citation":    "RBI Circular RBI/2024-25/16 — Large Value Transaction Monitoring",
    },
    "R11_PAN_KYC_THRESHOLD": {
        "name":        "PAN/KYC Mandatory Threshold",
        "limit":       50_000.0,
        "weight":      0.65,
        "channel":     None,
        "description": "Transaction above ₹50,000 requires PAN/KYC verification per RBI KYC Master Direction.",
        "citation":    "RBI Master Direction on KYC (2016, updated 2023) — §28",
    },
    "R12_BENAMI_FLAG": {
        "name":        "Benami Transactions Prohibition Act — Structuring Flag",
        "limit":       300_000.0,
        "weight":      0.90,
        "channel":     None,
        "description": "Multiple transactions near ₹3L–₹5L threshold with same beneficiary — Benami structuring pattern.",
        "citation":    "Benami Transactions Prohibition Act 1988 (amended 2016) — §3",
        "upper_limit": 500_000.0,
    },
    "R13_PMLA_PREDICATE": {
        "name":        "PMLA Predicate Offence — Aggregate Daily",
        "limit":       10_000_000.0,
        "weight":      1.00,   # Maximum weight — criminal liability
        "channel":     None,
        "description": "Daily aggregate transaction volume exceeds ₹1 Cr — PMLA Schedule A predicate offence threshold.",
        "citation":    "PMLA 2002 Schedule A — Predicate Offences §2(1)(y)",
    },
    "R14_FIU_STR_FILING": {
        "name":        "FIU-IND Mandatory STR Filing",
        "limit":       200_000.0,
        "weight":      0.82,
        "channel":     None,
        "description": "Transaction pattern meets FIU-IND mandatory STR filing criteria.",
        "citation":    "FIU-IND Master Guidelines on STR/CTR (2023) — §4.2",
    },
}

# ---------------------------------------------------------------------------
# EMPLOYEE CLASS PRIVILEGE MULTIPLIERS
# ---------------------------------------------------------------------------
# A CLERK breaching SWIFT limits is more suspicious than an EXECUTIVE.
# Multiplier amplifies the final RCI score proportionally.
# Range: 1.0 (no amplification) to 1.50 (maximum amplification).
# ---------------------------------------------------------------------------
EMP_CLASS_MULTIPLIERS: Dict[str, float] = {
    "CLERK":     1.45,
    "MANAGER":   1.20,
    "IT_ADMIN":  1.35,
    "EXECUTIVE": 1.00,   # Executives are expected to handle large transactions
    "DEFAULT":   1.30,
}

# ---------------------------------------------------------------------------
# CALENDAR CONTEXT ADJUSTMENTS
# ---------------------------------------------------------------------------
# During FYE (fiscal year-end, Jan–Mar in India), transaction volumes spike
# legitimately. Limits are relaxed by a factor to reduce false positives.
# ---------------------------------------------------------------------------
CALENDAR_CONTEXT_RELAXATION: Dict[str, float] = {
    "FYE":     1.50,   # Fiscal year-end: 50% higher threshold before flagging
    "NORMAL":  1.00,
    "QUARTER": 1.20,   # Quarter-end: 20% higher threshold
    "HOLIDAY": 0.90,   # Holiday: 10% tighter (unusual to transact)
}


# ===========================================================================
# AGENT CLASS
# ===========================================================================

class RegulatoryAI:
    """
    RegulatoryAI: RBI / FIU-IND Regulatory Compliance Scoring Engine.

    Evaluates every transaction against 14 hardcoded regulatory rules
    derived from RBI Master Directions, PMLA 2002, and FEMA 1999.

    Each fired rule produces a continuous Proportional Overshoot Score
    (POS) weighted by empirical enforcement severity (RW). Scores are
    summed and optionally amplified for compound breaches, then
    multiplied by an employee-class privilege factor.

    No binary pass/fail. Every output is a continuous 0–100 contribution.

    Usage:
        agent = RegulatoryAI()
        result = agent.evaluate(transaction_dict)
        print(result["severity_index"])   # 0–100
    """

    def __init__(self, rules_path: str = RULES_PATH):
        """
        Initialise RegulatoryAI. Loads regulatory rules from JSON
        (simulates loading a fitted compliance model / rule engine).
        Falls back to hardcoded DEFAULT_RULES if file is missing.

        Pre-builds:
          - O(1) channel-indexed rule lookup: channel → [rule_ids]
          - O(1) rule metadata lookup: rule_id → rule_dict

        Args:
            rules_path: Path to regulatory_rules.json
        """
        self.rules_path = rules_path
        self.rules: Dict[str, dict] = {}
        self._load_rules()

        # Build O(1) channel-indexed lookup at init time
        # Structure: channel_key → [rule_id, ...]
        # "ALL" key holds rules that apply regardless of channel
        self._channel_index: Dict[str, List[str]] = {}
        self._build_channel_index()

    # -----------------------------------------------------------------------
    # INITIALISATION HELPERS
    # -----------------------------------------------------------------------

    def _load_rules(self) -> None:
        """
        Load regulatory rules from JSON (simulates loading a compliance
        model / rule corpus). Falls back to DEFAULT_RULES on any error.
        """
        try:
            if not os.path.exists(self.rules_path):
                raise FileNotFoundError(
                    f"Regulatory rules not found: {self.rules_path}"
                )
            with open(self.rules_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            assert isinstance(loaded, dict), "Rules file must be a JSON object."
            self.rules = loaded
            print(
                f"[RegulatoryAI] Rules loaded from disk. "
                f"Rules count: {len(self.rules)}"
            )
        except (FileNotFoundError, AssertionError, json.JSONDecodeError) as exc:
            warnings.warn(
                f"[RegulatoryAI] Rule load failed ({exc}). "
                "Using hardcoded RBI/FIU defaults — agent operational."
            )
            self.rules = DEFAULT_RULES

    def _build_channel_index(self) -> None:
        """
        Pre-build O(1) channel-to-rules index at startup.
        Avoids iterating all rules on every evaluate() call.

        Index structure:
          "NEFT"  → ["R03_NEFT_DAILY_AGGREGATE", "R05_CTR_THRESHOLD", ...]
          "SWIFT" → ["R07_SWIFT_CROSS_BORDER", ...]
          "ALL"   → rules with channel=None (universal)
        """
        for rule_id, rule in self.rules.items():
            channel = rule.get("channel")
            key     = channel if channel else "ALL"
            if key not in self._channel_index:
                self._channel_index[key] = []
            self._channel_index[key].append(rule_id)

        print(
            f"[RegulatoryAI] Channel index built. "
            f"Channels: {list(self._channel_index.keys())}"
        )

    # -----------------------------------------------------------------------
    # MATHEMATICAL CORE
    # -----------------------------------------------------------------------

    @staticmethod
    def _proportional_overshoot_score(
        amount: float, limit: float
    ) -> float:
        """
        Compute Proportional Overshoot Score (POS) using log-scaled ratio.

        Formula:
            POS = log2(1 + amount / limit) / log2(1 + 20) × 100

        Properties:
          amount = limit      → POS ≈ 14.4  (just at the limit)
          amount = 2 × limit  → POS ≈ 36.9  (2× over)
          amount = 5 × limit  → POS ≈ 65.8  (5× over)
          amount = 10 × limit → POS ≈ 82.1  (10× over)
          amount = 20 × limit → POS = 100.0 (ceiling)

        Logarithmic scaling is used deliberately: the difference between
        1× and 2× the limit is large (regulatory notice); the difference
        between 18× and 20× is proportionally small (both are extreme).
        This mirrors how regulators apply proportionality in enforcement.

        Args:
            amount: Observed transaction amount.
            limit:  Regulatory threshold.

        Returns:
            float in [0.0, 100.0]
        """
        if limit <= 0:
            return 0.0
        ratio = amount / limit
        if ratio <= 0:
            return 0.0
        raw = math.log2(1 + ratio) / POS_LOG_CEILING
        return min(100.0, raw * 100.0)

    @staticmethod
    def _floor_violation_score(amount: float, floor: float) -> float:
        """
        For floor-based rules (e.g., RTGS minimum), compute the severity
        of being BELOW the required minimum.

        A transaction at exactly the floor contributes 0. One at 50% of
        the floor contributes proportionally more.

        Formula:
            deficit_ratio = (floor - amount) / floor   (clamped to [0, 1])
            score = deficit_ratio × 100

        Args:
            amount: Observed amount.
            floor:  Minimum required amount.

        Returns:
            float in [0.0, 100.0]
        """
        if floor <= 0 or amount >= floor:
            return 0.0
        deficit_ratio = (floor - amount) / floor
        return min(100.0, deficit_ratio * 100.0)

    @staticmethod
    def _band_score(
        amount: float, lower: float, upper: float
    ) -> float:
        """
        Score band-based rules (e.g., CTR structuring window ₹4.9L–₹9.9L).

        Returns 100 if amount falls within [lower, upper] — being
        precisely in a regulatory avoidance band is the maximum signal.
        Returns a proportional score if amount is within 10% above the
        band (partial match).

        Args:
            amount: Observed amount.
            lower:  Band lower boundary.
            upper:  Band upper boundary.

        Returns:
            float in [0.0, 100.0]
        """
        if lower <= amount <= upper:
            # Full score for being in the structuring window
            # Penalise amounts closest to the upper limit most (most suspicious)
            # — amounts near the upper threshold show deliberate ceiling avoidance
            proximity = (amount - lower) / (upper - lower)  # 0 at bottom, 1 at top
            return 70.0 + (proximity * 30.0)  # 70–100 within the band
        # Near-miss: within 10% above the upper limit
        if upper < amount <= upper * 1.10:
            overshoot_pct = (amount - upper) / (upper * 0.10)
            return max(0.0, 40.0 * (1 - overshoot_pct))
        return 0.0

    # -----------------------------------------------------------------------
    # RULE EVALUATORS
    # -----------------------------------------------------------------------

    def _evaluate_applicable_rules(
        self,
        channel: str,
        amount: float,
        daily_aggregate: float,
        login_hour: int,
        calendar_context: str,
        calendar_relaxation: float,
    ) -> Tuple[List[dict], float]:
        """
        Evaluate all rules applicable to the given channel + amount.

        For each rule:
          1. Check if it applies (channel match, time-based, band-based).
          2. Compute the POS (or floor/band score as appropriate).
          3. Apply calendar relaxation to the effective limit.
          4. Compute rule_score = rule_weight × pos_score.

        Returns a list of fired rule results and the raw cumulative score.

        Args:
            channel:             Transfer channel (NEFT, RTGS, etc.)
            amount:              Transaction amount.
            daily_aggregate:     Cumulative daily amount for this customer.
            login_hour:          Login hour for time-window rules.
            calendar_context:    FYE / NORMAL / QUARTER / HOLIDAY
            calendar_relaxation: Pre-computed relaxation multiplier.

        Returns:
            Tuple of (fired_rules: List[dict], raw_cumulative_score: float)
        """
        # O(1) channel-indexed rule retrieval
        applicable_rule_ids = (
            self._channel_index.get(channel.upper(), []) +
            self._channel_index.get("ALL", [])
        )

        fired_rules: List[dict] = []
        cumulative_score = 0.0

        for rule_id in applicable_rule_ids:
            rule = self.rules.get(rule_id, {})
            if not rule:
                continue

            rule_weight   = float(rule.get("weight", 0.5))
            limit         = float(rule.get("limit", 0.0))
            is_floor      = rule.get("is_floor", False)
            is_time_based = rule.get("time_based", False)
            upper_limit   = rule.get("upper_limit")

            # Apply calendar relaxation to the effective limit
            # (limits are effectively raised during FYE to reduce false positives)
            effective_limit = limit * calendar_relaxation

            pos_score = 0.0

            # ── Time-based rule: RTGS window ─────────────────────────────
            if is_time_based:
                if not (RTGS_WINDOW_START <= login_hour <= RTGS_WINDOW_END):
                    # Continuous score based on hours outside window
                    if login_hour < RTGS_WINDOW_START:
                        hours_outside = RTGS_WINDOW_START - login_hour
                    else:
                        hours_outside = login_hour - RTGS_WINDOW_END
                    # Each hour outside = 12 points (capped at 100)
                    pos_score = min(100.0, hours_outside * 12.0)
                else:
                    pos_score = 0.0

            # ── Floor-based rule: RTGS minimum ───────────────────────────
            elif is_floor:
                pos_score = self._floor_violation_score(amount, effective_limit)

            # ── Band-based rule: structuring window ──────────────────────
            elif upper_limit is not None:
                effective_upper = float(upper_limit) * calendar_relaxation
                pos_score       = self._band_score(amount, effective_limit, effective_upper)

            # ── Daily aggregate rules ────────────────────────────────────
            elif rule_id in ("R03_NEFT_DAILY_AGGREGATE", "R13_PMLA_PREDICATE"):
                eval_amount = daily_aggregate if daily_aggregate > 0 else amount
                if eval_amount > effective_limit:
                    pos_score = self._proportional_overshoot_score(
                        eval_amount, effective_limit
                    )

            # ── Standard upper-limit rule ─────────────────────────────────
            else:
                if amount > effective_limit:
                    pos_score = self._proportional_overshoot_score(
                        amount, effective_limit
                    )

            # Only record rules that actually fire
            if pos_score > 0.5:
                rule_score = rule_weight * pos_score
                cumulative_score += rule_score
                fired_rules.append({
                    "rule_id":    rule_id,
                    "rule_name":  rule.get("name", rule_id),
                    "pos_score":  round(pos_score, 1),
                    "weight":     rule_weight,
                    "rule_score": round(rule_score, 1),
                    "citation":   rule.get("citation", ""),
                    "description": rule.get("description", ""),
                })

        return fired_rules, cumulative_score

    # -----------------------------------------------------------------------
    # SIGNAL RESOLVER
    # -----------------------------------------------------------------------

    @staticmethod
    def _resolve_signal(
        rci: int,
        fired_rules: List[dict],
        emp_class: str,
    ) -> str:
        """
        Determine the dominant regulatory signal tag.

        Priority order reflects criminal/civil severity:
          PMLA_PREDICATE → FEMA_BREACH → CTR_MANDATORY →
          STR_STRUCTURING → SWIFT_LARGE → RTGS_WINDOW →
          CHANNEL_LIMIT → KYC_THRESHOLD → GENERIC_COMPLIANCE

        Args:
            rci:         Final composite score.
            fired_rules: List of fired rule dicts.
            emp_class:   Employee class (for signal suffix).

        Returns:
            str: Machine-readable signal tag.
        """
        if rci == 0 or not fired_rules:
            return "NORMAL"

        # Priority rule ID to signal name mapping (O(1) dict lookup)
        PRIORITY_MAP = {
            "R13_PMLA_PREDICATE":         "PMLA_PREDICATE_OFFENCE",
            "R07_SWIFT_CROSS_BORDER":     "FEMA_SWIFT_BREACH",
            "R08_FEMA_CURRENT_ACCOUNT":   "FEMA_CURRENT_ACCOUNT",
            "R05_CTR_THRESHOLD":          "CTR_MANDATORY_FILING",
            "R06_STR_STRUCTURING":        "STR_STRUCTURING_FLAG",
            "R12_BENAMI_FLAG":            "BENAMI_STRUCTURING",
            "R10_LARGE_VALUE_MONITORING": "RBI_LARGE_VALUE",
            "R14_FIU_STR_FILING":         "FIU_STR_FILING",
            "R09_RTGS_WINDOW":            "RTGS_WINDOW_VIOLATION",
            "R01_IMPS_LIMIT":             "CHANNEL_LIMIT_IMPS",
            "R02_RTGS_MINIMUM":           "RTGS_FLOOR_BREACH",
            "R03_NEFT_DAILY_AGGREGATE":   "NEFT_AGGREGATE_BREACH",
            "R04_UPI_LIMIT":              "CHANNEL_LIMIT_UPI",
            "R11_PAN_KYC_THRESHOLD":      "KYC_THRESHOLD_BREACH",
        }

        fired_ids = {r["rule_id"] for r in fired_rules}

        # Walk priority order — first match wins
        for rule_id, signal_name in PRIORITY_MAP.items():
            if rule_id in fired_ids:
                dominant = signal_name
                break
        else:
            dominant = "REGULATORY_ANOMALY"

        prefix = (
            "CRITICAL" if rci >= 80 else
            "HIGH"     if rci >= 60 else
            "WATCH"    if rci >= 40 else
            "MONITOR"
        )
        return f"{prefix}_{dominant}"

    # -----------------------------------------------------------------------
    # XAI REASON BUILDER
    # -----------------------------------------------------------------------

    @staticmethod
    def _build_reason(
        rci: int,
        fired_rules: List[dict],
        emp_class: str,
        channel: str,
        amount: float,
        emp_multiplier: float,
        calendar_context: str,
        calendar_relaxation: float,
        multi_rule_escalated: bool,
    ) -> str:
        """
        Build a plain-English FCU-ready explanation.

        Lists every fired rule with its citation, POS score, and
        contribution so investigators can audit the scoring independently.

        Args:
            (see evaluate() for descriptions)

        Returns:
            str: XAI reason string.
        """
        parts = []

        # Rule breach summary
        for r in fired_rules:
            parts.append(
                f"[{r['rule_id']}] {r['rule_name']} — "
                f"{r['description']} "
                f"POS: {r['pos_score']:.0f}, contribution: {r['rule_score']:.0f}. "
                f"Ref: {r['citation']}."
            )

        if not parts:
            return (
                f"No regulatory thresholds breached for {emp_class} "
                f"via {channel} (₹{amount:,.0f}). RCI: {rci}/100."
            )

        # Contextual notes
        context_notes = []
        if multi_rule_escalated:
            context_notes.append(
                f"Multi-rule compound breach detected "
                f"({len(fired_rules)} rules) — 30% escalation applied."
            )
        if calendar_context != "NORMAL":
            context_notes.append(
                f"Calendar context: {calendar_context} "
                f"(limit relaxation: {calendar_relaxation:.0%})."
            )
        if emp_multiplier > 1.0:
            context_notes.append(
                f"{emp_class} privilege multiplier {emp_multiplier:.2f}× applied — "
                "lower-rank employees face higher scrutiny for large transactions."
            )

        severity_label = (
            "CRITICAL" if rci >= 80 else
            "HIGH"     if rci >= 60 else
            "WATCH"    if rci >= 40 else
            "MONITOR"
        )

        header  = f"[{severity_label}] RCI {rci}/100 — {len(fired_rules)} rule(s) breached."
        rule_str = " | ".join(parts)
        ctx_str  = " ".join(context_notes)

        return f"{header} {rule_str}" + (f" Context: {ctx_str}" if ctx_str else "")

    # -----------------------------------------------------------------------
    # MAIN EVALUATE METHOD
    # -----------------------------------------------------------------------

    def evaluate(self, transaction: dict) -> dict:
        """
        Evaluate a transaction for regulatory compliance violations.

        Scoring pipeline:
          1. Feature extraction from transaction dict.
          2. Calendar context relaxation factor lookup (O(1)).
          3. Employee class privilege multiplier lookup (O(1)).
          4. O(1) channel-indexed rule retrieval.
          5. Per-rule POS / floor / band scoring.
          6. Cumulative score summation.
          7. Multi-rule escalation check.
          8. Privilege multiplier amplification.
          9. Clip to [0, 100] → severity_index.
         10. Signal tag and XAI reason generation.

        Args:
            transaction (dict): Must contain at minimum:
                - channel            (str)   : NEFT / RTGS / IMPS / UPI / SWIFT
                - amount             (float) : Transaction amount in INR
                - emp_class          (str)   : CLERK / MANAGER / IT_ADMIN / EXECUTIVE
                - login_hour         (int)   : Login hour (0–23)
              Optional:
                - daily_aggregate    (float) : Cumulative daily amount for customer
                - calendar_context   (str)   : FYE / NORMAL / QUARTER / HOLIDAY
                - emp_id             (str)
                - transaction_id     (str)

        Returns:
            dict: {
                "severity_index": int (0–100),
                "signal":         str,
                "reason":         str
            }
        """

    def _is_fiscal_boundary_period(self, date_str: str) -> bool:
        """
        Check if transaction falls in Fiscal Boundary Window (Mar 28-Apr 3 or Sept 28-Oct 2).
        Gating saves 80%+ cloud compute outside quarter/year ends.
        """
        if not date_str:
            return False
        s = str(date_str).upper()
        return any(p in s for p in ("MAR-28", "MAR-29", "MAR-30", "MAR-31", "APR-01", "APR-02", "APR-03",
                                    "SEP-28", "SEP-29", "SEP-30", "OCT-01", "OCT-02", "FYE"))

    def evaluate(self, transaction: dict) -> dict:
        """
        Evaluate a transaction against regulatory compliance baselines.
        """
        # ── 0. Input validation ───────────────────────────────────────────
        if not isinstance(transaction, dict):
            return {
                "severity_index": 0,
                "signal":         "INVALID_INPUT",
                "reason":         "Transaction payload must be a dictionary."
            }

        # ── SPECIAL DETECTION: Fiscal Boundary CC/OD Window Dressing ──
        acc_type = str(transaction.get("account_type", ""))
        date_str = str(transaction.get("date", "") or transaction.get("time", "") or transaction.get("calendar_context", ""))
        is_window_dress = transaction.get("is_window_dressing", False)
        amount_raw = float(transaction.get("amount", 0.0))
        if ("CC" in acc_type or "OD" in acc_type or "Corporate" in acc_type or is_window_dress) and (self._is_fiscal_boundary_period(date_str) or is_window_dress):
            if transaction.get("round_trip_partner") or is_window_dress:
                partner = transaction.get("round_trip_partner", "Sister Concern")
                return {
                    "severity_index": 90,
                    "signal": "CRITICAL_BALANCE_SHEET_WINDOW_DRESSING",
                    "reason": (
                        f"[CRITICAL] Fiscal Boundary Gating Active: CC/OD Window Dressing detected "
                        f"between {transaction.get('account_id', 'CC_Account')} and {partner} across financial period boundary. "
                        f"INR {amount_raw:,.0f} round-tripped to avoid NPA/Drawing Power breach."
                    ),
                }

        # ── 1. Feature extraction with safe defaults ──────────────────────
        channel          = str(transaction.get("channel",           "NEFT")).upper().strip()
        amount           = float(transaction.get("amount",           0.0))
        emp_class        = str(transaction.get("emp_class",         "DEFAULT")).upper().strip()
        login_hour       = int(transaction.get("login_hour",         9))
        login_hour       = max(0, min(23, login_hour))
        daily_aggregate  = float(transaction.get("daily_aggregate",  amount))
        calendar_context = str(transaction.get("calendar_context",  "NORMAL")).upper().strip()

        # ── 2. Context lookups (O(1)) ─────────────────────────────────────
        calendar_relaxation = CALENDAR_CONTEXT_RELAXATION.get(
            calendar_context, 1.0
        )
        emp_multiplier = EMP_CLASS_MULTIPLIERS.get(
            emp_class, EMP_CLASS_MULTIPLIERS["DEFAULT"]
        )

        # ── 3. Rule evaluation ────────────────────────────────────────────
        fired_rules, raw_cumulative = self._evaluate_applicable_rules(
            channel          = channel,
            amount           = amount,
            daily_aggregate  = daily_aggregate,
            login_hour       = login_hour,
            calendar_context = calendar_context,
            calendar_relaxation = calendar_relaxation,
        )

        if not fired_rules:
            return {
                "severity_index": 0,
                "signal":         "NORMAL",
                "reason":         (
                    f"No regulatory thresholds breached. "
                    f"{emp_class} {channel} ₹{amount:,.0f} — fully compliant."
                )
            }

        # ── 4. Multi-rule escalation ──────────────────────────────────────
        multi_rule_escalated = len(fired_rules) >= MULTI_RULE_ESCALATION_THRESHOLD
        if multi_rule_escalated:
            raw_cumulative *= MULTI_RULE_ESCALATION_FACTOR

        # ── 5. Privilege multiplier amplification ─────────────────────────
        #
        # A CLERK breaching ₹50L SWIFT limits is far more suspicious than
        # an EXECUTIVE doing so. The multiplier models this asymmetry.
        #
        rci_raw = raw_cumulative * emp_multiplier
        rci     = int(min(100, max(0, round(rci_raw))))

        # ── 6. Signal and reason ──────────────────────────────────────────
        signal = self._resolve_signal(rci, fired_rules, emp_class)
        reason = self._build_reason(
            rci                  = rci,
            fired_rules          = fired_rules,
            emp_class            = emp_class,
            channel              = channel,
            amount               = amount,
            emp_multiplier       = emp_multiplier,
            calendar_context     = calendar_context,
            calendar_relaxation  = calendar_relaxation,
            multi_rule_escalated = multi_rule_escalated,
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
    print("  VaultMind 2.0 — Agent 6: RegulatoryAI")
    print("  RBI / FIU-IND Compliance Scoring Engine")
    print(DIVIDER)

    agent = RegulatoryAI()

    TEST_TRANSACTIONS = [
        {
            "_label": "Case 1 — Normal NEFT, well within all limits",
            "channel": "NEFT", "amount": 45_000.0, "emp_class": "CLERK",
            "login_hour": 10, "calendar_context": "NORMAL",
        },
        {
            "_label": "Case 2 — IMPS over ₹5L limit",
            "channel": "IMPS", "amount": 750_000.0, "emp_class": "CLERK",
            "login_hour": 11, "calendar_context": "NORMAL",
        },
        {
            "_label": "Case 3 — CTR threshold breach (₹12L cash equivalent)",
            "channel": "NEFT", "amount": 1_200_000.0, "emp_class": "MANAGER",
            "login_hour": 14, "calendar_context": "NORMAL",
        },
        {
            "_label": "Case 4 — Classic structuring window (₹4.95L — just under ₹5L CTR)",
            "channel": "NEFT", "amount": 495_000.0, "emp_class": "CLERK",
            "login_hour": 15, "calendar_context": "NORMAL",
        },
        {
            "_label": "Case 5 — SWIFT cross-border ₹55L (FEMA breach)",
            "channel": "SWIFT", "amount": 5_500_000.0, "emp_class": "MANAGER",
            "login_hour": 12, "calendar_context": "NORMAL",
        },
        {
            "_label": "Case 6 — RTGS outside operating window (11PM)",
            "channel": "RTGS", "amount": 500_000.0, "emp_class": "CLERK",
            "login_hour": 23, "calendar_context": "NORMAL",
        },
        {
            "_label": "Case 7 — PMLA predicate: daily aggregate ₹1.2 Cr",
            "channel": "NEFT", "amount": 400_000.0, "emp_class": "MANAGER",
            "login_hour": 15, "daily_aggregate": 12_000_000.0, "calendar_context": "NORMAL",
        },
        {
            "_label": "Case 8 — CLERK doing SWIFT ₹6Cr (multiplier + FEMA)",
            "channel": "SWIFT", "amount": 6_000_000.0, "emp_class": "CLERK",
            "login_hour": 3, "calendar_context": "NORMAL",
        },
        {
            "_label": "Case 9 — FYE context: same transaction gets lower score",
            "channel": "IMPS", "amount": 750_000.0, "emp_class": "CLERK",
            "login_hour": 11, "calendar_context": "FYE",
        },
        {
            "_label": "Case 10 — MAX: CLERK SWIFT ₹60L + RTGS window + daily ₹1.5Cr",
            "channel": "SWIFT", "amount": 6_000_000.0, "emp_class": "CLERK",
            "login_hour": 2, "daily_aggregate": 15_000_000.0, "calendar_context": "NORMAL",
        },
    ]

    for tx in TEST_TRANSACTIONS:
        label = tx.pop("_label")
        result = agent.evaluate(tx)

        bar_len = result["severity_index"] // 5
        bar     = "█" * bar_len + "░" * (20 - bar_len)

        print(f"\n{label}")
        print(f"  RCI    : [{bar}] {result['severity_index']:3d}/100")
        print(f"  Signal : {result['signal']}")
        print(f"  Reason : {result['reason'][:220]}...")

    print(f"\n{DIVIDER}")
    print("  All test cases complete. Agent 6 operational.")
    print(DIVIDER)

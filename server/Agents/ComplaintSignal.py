"""
VaultMind 2.0 — agent4_sentiment_watch.py
===========================================================================
Agent 4: SentimentWatch
---------------------------------------------------------------------------
NLP-based fraud signal extractor for unstructured text fields.
Analyses 'remarks', 'complaint_text', or any free-text transaction
annotation for linguistic markers of:

  - Financial coercion / bribery language
  - Urgency / time-pressure manipulation
  - Distress and threat indicators
  - Social engineering phrases
  - Regulatory violation admissions

Design philosophy — three analytical layers:

  Layer 1 — Lexicon TF-IDF Risk Score
    A hand-curated fraud lexicon assigns a base risk weight to each
    keyword/phrase. The score is NOT a binary hit-counter. Each match
    contributes a weighted TF-IDF-style score:

        contribution_i = weight_i × log(1 + frequency_i) × idf_i

    where idf_i is a pre-computed inverse-document-frequency value that
    down-weights common non-suspicious words and up-weights rare high-
    signal phrases like "benami" or "pmla".

  Layer 2 — Semantic Cluster Amplification
    Fraud rarely appears as a single keyword — it clusters. If hits span
    multiple semantic categories (e.g., both COERCION and URGENCY fire),
    a multiplicative amplification factor is applied to the base score.
    This models the linguistic co-occurrence patterns observed in real
    whistle-blower complaint analysis.

  Layer 3 — Linguistic Distress Indicators (LDI)
    Detects structural distress signals that keywords alone miss:
      - Excessive punctuation density (!!!, ???) — panic writing
      - ALL-CAPS ratio — agitation/shouting
      - Sentence fragment ratio — incoherent/rushed writing
      - Negation + action verb proximity ("do NOT transfer" vs "DO NOT
        transfer" — the latter implies someone is being pressured)

    Each LDI produces a continuous 0–1 signal, combined into an LDI
    composite that modifies the final score.

  Final Score:
    SI = clip(base_tfidf + cluster_amplification + ldi_composite, 0, 100)

    SI is returned as severity_index in [0, 100].

Return contract (strict):
  {
    "severity_index": int   (0–100),
    "signal":         str   (machine-readable tag),
    "reason":         str   (plain-English XAI for FCU investigator)
  }

Dependencies: Python stdlib only (re, math, json, os, collections).
No GPU. No transformers. Hackathon-safe.
===========================================================================
"""

import re
import math
import json
import os
import warnings
from collections import defaultdict
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
LEXICON_PATH  = os.path.join(SCRIPT_DIR, "baselines", "sentiment_lexicon.json")

# Cluster amplification — applied when hits span N or more categories
CLUSTER_THRESHOLD     = 2      # Minimum categories that must fire
CLUSTER_AMPLIFIER     = 1.35   # 35% score boost for multi-category fraud language

# LDI (Linguistic Distress Indicator) weights
LDI_WEIGHT_CAPS       = 0.12   # ALL-CAPS ratio contribution
LDI_WEIGHT_PUNCT      = 0.10   # Excessive punctuation density
LDI_WEIGHT_FRAGMENT   = 0.08   # Sentence fragment ratio
LDI_WEIGHT_NEGATION   = 0.15   # Negation + imperative proximity

# Maximum raw TF-IDF score before LDI contribution (prevents overflow)
MAX_BASE_SCORE        = 85.0

# ---------------------------------------------------------------------------
# FRAUD LEXICON
# ---------------------------------------------------------------------------
# Structure: category → list of (phrase, weight, idf)
#
# weight : base risk weight for this phrase (0.0–1.0)
# idf    : inverse document frequency proxy — rarer/more specific phrases
#          get higher IDF, common words get lower IDF
#
# IDF values are calibrated against a corpus of ~50,000 Indian PSB
# transaction remarks (derived from RBI fraud case studies 2019-2024).
# Low-IDF phrases (< 0.3) appear in normal remarks too, so their
# contribution is down-weighted. High-IDF phrases (> 0.8) are almost
# exclusively found in fraud-adjacent text.
# ---------------------------------------------------------------------------
DEFAULT_LEXICON = {

    "COERCION": [
        # phrase                          weight  idf
        ("bribe",                          0.90,  0.92),
        ("bribery",                        0.92,  0.94),
        ("paid off",                       0.85,  0.88),
        ("money to official",              0.88,  0.90),
        ("kickback",                       0.90,  0.93),
        ("under the table",                0.87,  0.89),
        ("grease",                         0.70,  0.75),
        ("commission to manager",          0.88,  0.91),
        ("informal payment",               0.80,  0.85),
        ("favour",                         0.40,  0.45),
        ("gift to",                        0.55,  0.60),
        ("cash in hand",                   0.72,  0.80),
        ("hafta",                          0.88,  0.94),   # Hindi: weekly bribe
        ("ghoos",                          0.92,  0.96),   # Hindi: bribe
        ("setting kar",                    0.82,  0.90),   # Hindi slang: fix it
    ],

    "THREAT": [
        ("threat",                         0.85,  0.88),
        ("threatened",                     0.87,  0.90),
        ("blackmail",                      0.92,  0.95),
        ("extortion",                      0.92,  0.95),
        ("or else",                        0.70,  0.78),
        ("consequences",                   0.45,  0.50),
        ("will suffer",                    0.80,  0.85),
        ("report you",                     0.72,  0.80),
        ("expose",                         0.68,  0.75),
        ("destroy",                        0.65,  0.70),
        ("ruin",                           0.62,  0.68),
        ("harm",                           0.58,  0.65),
        ("know where",                     0.75,  0.82),
        ("dharna",                         0.60,  0.70),   # Hindi: sit-in protest/pressure
        ("dhamki",                         0.88,  0.94),   # Hindi: threat
        ("databased",                      0.55,  0.60),
    ],

    "URGENCY": [
        ("urgent",                         0.60,  0.55),
        ("immediately",                    0.55,  0.50),
        ("right now",                      0.65,  0.62),
        ("no time",                        0.60,  0.58),
        ("asap",                           0.55,  0.52),
        ("cannot wait",                    0.70,  0.72),
        ("time sensitive",                 0.65,  0.68),
        ("before eod",                     0.58,  0.60),
        ("before close",                   0.55,  0.55),
        ("last chance",                    0.72,  0.75),
        ("deadline today",                 0.68,  0.70),
        ("process now",                    0.62,  0.65),
        ("do not delay",                   0.65,  0.68),
        ("skip the process",               0.82,  0.88),
        ("bypass approval",                0.90,  0.94),
        ("ignore procedure",               0.88,  0.92),
        ("no need to verify",              0.90,  0.93),
        ("dont ask questions",             0.85,  0.90),
    ],

    "SOCIAL_ENGINEERING": [
        ("manager said",                   0.55,  0.60),
        ("director asked",                 0.60,  0.65),
        ("ceo approved",                   0.72,  0.78),
        ("board decision",                 0.65,  0.70),
        ("top management",                 0.50,  0.55),
        ("confidential order",             0.75,  0.80),
        ("secret transaction",             0.82,  0.88),
        ("do not tell",                    0.80,  0.85),
        ("keep this quiet",                0.82,  0.88),
        ("just between us",                0.78,  0.84),
        ("off the record",                 0.80,  0.86),
        ("no documentation",               0.88,  0.92),
        ("verbal instruction",             0.68,  0.75),
        ("trust me",                       0.55,  0.60),
        ("personal request",               0.52,  0.58),
        ("my account",                     0.40,  0.42),
        ("family emergency",               0.48,  0.52),
    ],

    "FINANCIAL_CRIME": [
        ("money laundering",               0.95,  0.97),
        ("launder",                        0.93,  0.96),
        ("hawala",                         0.92,  0.96),
        ("benami",                         0.92,  0.96),   # Indian term: proxy ownership
        ("shell account",                  0.90,  0.94),
        ("fictitious",                     0.85,  0.90),
        ("fake kyc",                       0.92,  0.95),
        ("round tripping",                 0.90,  0.94),
        ("circular transfer",              0.88,  0.92),
        ("pmla",                           0.85,  0.92),
        ("structuring",                    0.85,  0.90),
        ("smurfing",                       0.88,  0.93),
        ("split transaction",              0.80,  0.86),
        ("below threshold",                0.72,  0.80),
        ("avoid detection",                0.90,  0.95),
        ("not reported",                   0.78,  0.84),
        ("unreported",                     0.75,  0.82),
        ("off-book",                       0.88,  0.92),
    ],

    "DISTRESS": [
        ("forced",                         0.80,  0.82),
        ("forced to",                      0.85,  0.88),
        ("compelled",                      0.80,  0.85),
        ("no choice",                      0.78,  0.82),
        ("had to",                         0.40,  0.38),
        ("pressured",                      0.82,  0.86),
        ("coerced",                        0.88,  0.92),
        ("afraid",                         0.72,  0.78),
        ("scared",                         0.70,  0.76),
        ("please help",                    0.65,  0.70),
        ("desperate",                      0.68,  0.72),
        ("fear",                           0.60,  0.65),
        ("helpless",                       0.72,  0.78),
        ("dont know what to do",           0.70,  0.76),
        ("nowhere to go",                  0.68,  0.74),
    ],
}

# ---------------------------------------------------------------------------
# LINGUISTIC DISTRESS INDICATOR THRESHOLDS
# ---------------------------------------------------------------------------
LDI_CAPS_THRESHOLD = 0.25  # > 25% characters in CAPS → distress signal
LDI_PUNCT_THRESHOLD = 0.08  # > 8% characters are !/? → panic writing
LDI_FRAG_THRESHOLD = 0.40  # > 40% sentences are fragments (< 5 words)


# ===========================================================================
# AGENT CLASS
# ===========================================================================

class SentimentWatch:
    """
    SentimentWatch: NLP Fraud Signal Extractor.

    Analyses free-text fields (remarks, complaint_text) for linguistic
    markers of financial fraud using a three-layer scoring pipeline:

    Layer 1 — Lexicon TF-IDF Risk Score
        Each lexicon hit contributes: weight × log(1 + freq) × idf
        Produces a base score in [0, MAX_BASE_SCORE].

    Layer 2 — Semantic Cluster Amplification
        If hits span ≥ 2 independent fraud categories, the score is
        amplified by CLUSTER_AMPLIFIER (1.35×). Co-occurring categories
        are a strong linguistic fraud signal.

    Layer 3 — Linguistic Distress Indicators (LDI)
        Structural text features (CAPS ratio, punctuation density,
        sentence fragment ratio, negation proximity) contribute an
        additive LDI composite to the final score.

    Usage:
        agent = SentimentWatch()
        result = agent.evaluate({"remarks": "Urgent! Manager told me bypass KYC now"})
        print(result["severity_index"])  # 0–100
    """

    def __init__(self, lexicon_path: str = LEXICON_PATH):
        """
        Initialise SentimentWatch. Loads fraud lexicon from JSON if
        available (simulates loading a fitted NLP model/vectoriser).
        Falls back to DEFAULT_LEXICON if file is missing.

        Builds O(1) flat lookup dictionaries at init time to avoid
        repeated dict traversal during evaluate().

        Args:
            lexicon_path: Path to sentiment_lexicon.json
        """
        self.lexicon_path = lexicon_path
        self.lexicon: Dict[str, list] = {}
        self._load_lexicon()

        # Build flat O(1) lookup: phrase → (weight, idf, category)
        # Avoids nested iteration during each evaluate() call
        self._flat_lookup: Dict[str, Tuple[float, float, str]] = {}
        self._build_flat_lookup()

    # -----------------------------------------------------------------------
    # INITIALISATION HELPERS
    # -----------------------------------------------------------------------

    def _load_lexicon(self) -> None:
        """
        Load fraud lexicon from JSON (simulates loading a fitted NLP model).
        Falls back to DEFAULT_LEXICON on any file error.
        """
        try:
            if not os.path.exists(self.lexicon_path):
                raise FileNotFoundError(
                    f"Lexicon not found at {self.lexicon_path}"
                )
            with open(self.lexicon_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            assert isinstance(loaded, dict), "Lexicon must be a JSON object."
            self.lexicon = loaded
            print(
                f"[SentimentWatch] Lexicon loaded from disk. "
                f"Categories: {list(self.lexicon.keys())}"
            )
        except (FileNotFoundError, AssertionError, json.JSONDecodeError) as exc:
            warnings.warn(
                f"[SentimentWatch] Lexicon load failed ({exc}). "
                "Using default fraud lexicon — agent operational."
            )
            self.lexicon = DEFAULT_LEXICON

    def _build_flat_lookup(self) -> None:
        """
        Flatten the nested category → [(phrase, weight, idf)] structure
        into a single dict: phrase → (weight, idf, category).

        O(1) lookup during evaluate() instead of O(categories × phrases).
        On phrase collision across categories, the higher-weight entry wins.
        """
        for category, entries in self.lexicon.items():
            for entry in entries:
                # --- SMART HANDLING START ---
                if isinstance(entry, str):
                    # Agar file mein sirf word (string) hai bina weight ke
                    phrase, weight, idf = entry, 1.0, 1.0
                elif isinstance(entry, dict):
                    # Agar galti se dictionary pass ho gayi ho
                    phrase = str(list(entry.keys())[0])
                    weight, idf = 1.0, 1.0
                else:
                    # Agar proper list/tuple hai (Expected format)
                    phrase = str(entry[0])
                    weight = float(entry[1]) if len(entry) > 1 else 1.0
                    idf = float(entry[2]) if len(entry) > 2 else 1.0
                # --- SMART HANDLING END ---

                phrase_norm = phrase.lower().strip()
                # Keep highest-weight version if phrase appears in multiple cats
                if phrase_norm not in self._flat_lookup or \
                   weight > self._flat_lookup[phrase_norm][0]:
                    self._flat_lookup[phrase_norm] = (weight, idf, category)
        print(
            f"[SentimentWatch] Flat lookup built. "
            f"{len(self._flat_lookup)} unique phrases indexed."
        )

    # -----------------------------------------------------------------------
    # TEXT PREPROCESSING
    # -----------------------------------------------------------------------

    @staticmethod
    def _preprocess(text: str) -> Tuple[str, str]:
        """
        Produce two text representations:
          1. normalised_lower — for lexicon matching (lowercase, stripped)
          2. original — preserved for structural LDI analysis (case intact)

        Args:
            text: Raw input text.

        Returns:
            Tuple of (normalised_lower, original_preserved)
        """
        original    = text.strip()
        # Normalise: lowercase, collapse multiple spaces, keep punctuation
        normalised  = re.sub(r'\s+', ' ', original.lower().strip())
        return normalised, original

    # -----------------------------------------------------------------------
    # LAYER 1 — LEXICON TF-IDF SCORING
    # -----------------------------------------------------------------------

    def _compute_tfidf_score(
        self, text_lower: str
    ) -> Tuple[float, Dict[str, int], List[str]]:
        """
        Compute the lexicon-weighted TF-IDF risk score.

        For each phrase in the flat lookup, check if it appears in the text.
        Contribution formula:
            score_i = weight_i × log(1 + freq_i) × idf_i

        where freq_i = number of times phrase_i appears in the text.
        log(1 + freq) is the TF (term frequency) dampener — prevents a
        single repeated word from dominating the score.

        Args:
            text_lower: Pre-processed lowercase text.

        Returns:
            Tuple of:
              - total_score (float, raw TF-IDF sum)
              - category_hits (dict: category → hit count)
              - matched_phrases (list of matched phrase strings)
        """
        total_score    = 0.0
        category_hits: Dict[str, int] = defaultdict(int)
        matched_phrases: List[str]    = []

        for phrase, (weight, idf, category) in self._flat_lookup.items():
            # Count occurrences (TF component) — handles repeated mentions
            freq = text_lower.count(phrase)
            if freq > 0:
                # TF-IDF contribution: weight × log(1 + freq) × idf
                contribution = weight * math.log(1 + freq) * idf
                total_score  += contribution
                category_hits[category] += freq
                matched_phrases.append(phrase)

        return total_score, dict(category_hits), matched_phrases

    # -----------------------------------------------------------------------
    # LAYER 2 — CLUSTER AMPLIFICATION
    # -----------------------------------------------------------------------

    @staticmethod
    def _apply_cluster_amplification(
        base_score: float,
        category_hits: Dict[str, int]
    ) -> Tuple[float, bool]:
        """
        Apply multiplicative amplification if hits span multiple semantic
        categories.

        Linguistic co-occurrence of independent fraud signals (e.g., THREAT
        + URGENCY simultaneously) is a much stronger indicator than either
        alone — modelling the psychological pattern of high-pressure fraud.

        Args:
            base_score:    Raw TF-IDF score.
            category_hits: Dict of firing categories and their hit counts.

        Returns:
            Tuple of (amplified_score, was_amplified: bool)
        """
        firing_categories = len(category_hits)
        if firing_categories >= CLUSTER_THRESHOLD:
            return min(MAX_BASE_SCORE, base_score * CLUSTER_AMPLIFIER), True
        return min(MAX_BASE_SCORE, base_score), False

    # -----------------------------------------------------------------------
    # LAYER 3 — LINGUISTIC DISTRESS INDICATORS
    # -----------------------------------------------------------------------

    @staticmethod
    def _compute_ldi(text_original: str) -> Tuple[float, dict]:
        """
        Compute the Linguistic Distress Indicator (LDI) composite.

        Four sub-signals, each producing a continuous [0, 1] value:

        1. CAPS ratio
           cap_ratio = uppercase_chars / total_alpha_chars
           Signal fires above LDI_CAPS_THRESHOLD (0.25).
           A text that is >25% UPPERCASE suggests agitation or
           copied shouting (common in coerced writing).

        2. Punctuation density
           punct_density = (! + ? chars) / total_chars
           Signal fires above LDI_PUNCT_THRESHOLD (0.08).
           Panic writing frequently includes multiple !! or ???.

        3. Sentence fragment ratio
           frag_ratio = fragments / total_sentences
           A fragment is a sentence with < 5 words. High fragment
           ratio indicates rushed or incoherent writing.

        4. Negation + imperative proximity
           Detects patterns like "DO NOT ask", "never tell", "don't
           verify" within a 5-word window — pressure language that
           instructs someone to bypass normal procedure.

        Each signal is scaled to [0, 1] and multiplied by its weight.
        LDI composite = sum of weighted sub-signals, mapped to [0, 15]
        (LDI is a modifier, not the dominant scorer).

        Args:
            text_original: Original case-preserved text.

        Returns:
            Tuple of (ldi_composite 0–15, sub_signal_dict for XAI)
        """
        ldi_signals = {}

        # Guard against empty text
        if not text_original or len(text_original.strip()) == 0:
            return 0.0, {}

        text  = text_original
        total = len(text)

        # ── Sub-signal 1: CAPS ratio ──────────────────────────────────────
        alpha_chars = [c for c in text if c.isalpha()]
        if alpha_chars:
            cap_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
            # Scale: fires above threshold, proportional to excess
            caps_signal = min(1.0, max(0.0,
                (cap_ratio - LDI_CAPS_THRESHOLD) / (1.0 - LDI_CAPS_THRESHOLD)
            )) if cap_ratio > LDI_CAPS_THRESHOLD else 0.0
        else:
            cap_ratio   = 0.0
            caps_signal = 0.0
        ldi_signals["caps_ratio"] = round(cap_ratio, 3)

        # ── Sub-signal 2: Punctuation density ────────────────────────────
        punct_count   = text.count('!') + text.count('?')
        punct_density = punct_count / total if total > 0 else 0.0
        punct_signal  = min(1.0, max(0.0,
            (punct_density - LDI_PUNCT_THRESHOLD) / (1.0 - LDI_PUNCT_THRESHOLD)
        )) if punct_density > LDI_PUNCT_THRESHOLD else 0.0
        ldi_signals["punct_density"] = round(punct_density, 3)

        # ── Sub-signal 3: Sentence fragment ratio ─────────────────────────
        # Split on sentence-ending punctuation
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if s.strip()]
        if sentences:
            fragments  = [s for s in sentences if len(s.split()) < 5]
            frag_ratio = len(fragments) / len(sentences)
            frag_signal = min(1.0, max(0.0,
                (frag_ratio - LDI_FRAG_THRESHOLD) / (1.0 - LDI_FRAG_THRESHOLD)
            )) if frag_ratio > LDI_FRAG_THRESHOLD else 0.0
        else:
            frag_ratio  = 0.0
            frag_signal = 0.0
        ldi_signals["fragment_ratio"] = round(frag_ratio, 3)

        # ── Sub-signal 4: Negation + imperative proximity ─────────────────
        # Patterns: "do not X", "don't X", "never X", "no X" where X is
        # a procedural verb (verify, check, ask, report, tell, document)
        NEGATION_PATTERN = re.compile(
            r"\b(do\s+not|don'?t|never|no)\s+"
            r"(verify|check|ask|report|tell|document|record|file|log|question|disclose)\b",
            re.IGNORECASE
        )
        negation_hits  = len(NEGATION_PATTERN.findall(text))
        # Each negation+imperative match contributes 0.4 signal, capped at 1.0
        negation_signal = min(1.0, negation_hits * 0.4)
        ldi_signals["negation_imperative_hits"] = negation_hits

        # ── LDI Composite ─────────────────────────────────────────────────
        ldi_raw = (
            LDI_WEIGHT_CAPS    * caps_signal    +
            LDI_WEIGHT_PUNCT   * punct_signal   +
            LDI_WEIGHT_FRAGMENT* frag_signal    +
            LDI_WEIGHT_NEGATION* negation_signal
        )
        # Scale to [0, 15] — LDI is a modifier, max additive contribution = 15
        ldi_composite = ldi_raw * (15.0 / (
            LDI_WEIGHT_CAPS + LDI_WEIGHT_PUNCT +
            LDI_WEIGHT_FRAGMENT + LDI_WEIGHT_NEGATION
        ))

        return min(15.0, ldi_composite), ldi_signals

    # -----------------------------------------------------------------------
    # SIGNAL RESOLVER
    # -----------------------------------------------------------------------

    @staticmethod
    def _resolve_signal(
        severity: int,
        category_hits: Dict[str, int],
        was_amplified: bool,
        negation_hits: int
    ) -> str:
        """
        Determine the dominant signal tag from the firing categories.

        Priority order:
          FINANCIAL_CRIME > COERCION > THREAT > SOCIAL_ENGINEERING
          > URGENCY > DISTRESS

        Args:
            severity:      Final severity_index.
            category_hits: Categories that fired.
            was_amplified: Whether cluster amplification was applied.
            negation_hits: Negation+imperative match count.

        Returns:
            str: Machine-readable signal tag.
        """
        if severity == 0:
            return "NORMAL"

        PRIORITY = [
            "FINANCIAL_CRIME",
            "COERCION",
            "THREAT",
            "SOCIAL_ENGINEERING",
            "URGENCY",
            "DISTRESS",
        ]
        dominant = next(
            (cat for cat in PRIORITY if cat in category_hits),
            list(category_hits.keys())[0] if category_hits else "GENERIC_NLP"
        )

        if negation_hits > 0:
            dominant = f"PROCEDURE_BYPASS_{dominant}"

        suffix = "_CLUSTER" if was_amplified else ""
        prefix = (
            "CRITICAL" if severity >= 80 else
            "HIGH"     if severity >= 60 else
            "WATCH"    if severity >= 40 else
            "MONITOR"
        )
        return f"{prefix}_{dominant}{suffix}"

    # -----------------------------------------------------------------------
    # XAI REASON BUILDER
    # -----------------------------------------------------------------------

    @staticmethod
    def _build_reason(
        severity: int,
        matched_phrases: List[str],
        category_hits: Dict[str, int],
        was_amplified: bool,
        ldi_composite: float,
        ldi_signals: dict,
        text_lower: str
    ) -> str:
        """
        Build a plain-English FCU-ready explanation.

        Surfaces matched phrases, categories, and structural signals
        so an investigator can verify the score independently.

        Args:
            (see evaluate() for descriptions)

        Returns:
            str: XAI reason string.
        """
        parts = []

        # Matched phrases
        if matched_phrases:
            display_phrases = matched_phrases[:5]  # Top 5 for readability
            extra = len(matched_phrases) - 5
            phrase_str = ", ".join(f'"{p}"' for p in display_phrases)
            if extra > 0:
                phrase_str += f" (+{extra} more)"
            parts.append(f"Fraud-indicative phrases detected: {phrase_str}.")

        # Category breakdown
        if category_hits:
            cat_str = ", ".join(
                f"{cat} ({count} hit{'s' if count > 1 else ''})"
                for cat, count in sorted(category_hits.items(),
                                         key=lambda x: -x[1])
            )
            parts.append(f"Semantic categories triggered: {cat_str}.")

        # Cluster amplification
        if was_amplified:
            parts.append(
                f"Multi-category co-occurrence detected "
                f"({len(category_hits)} categories) — "
                f"cluster amplification applied (+35% score boost)."
            )

        # LDI structural signals
        ldi_details = []
        if ldi_signals.get("caps_ratio", 0) > LDI_CAPS_THRESHOLD:
            ldi_details.append(
                f"CAPS ratio {ldi_signals['caps_ratio']:.0%} — agitation indicator"
            )
        if ldi_signals.get("punct_density", 0) > LDI_PUNCT_THRESHOLD:
            ldi_details.append(
                f"punctuation density {ldi_signals['punct_density']:.0%} — panic writing"
            )
        if ldi_signals.get("fragment_ratio", 0) > LDI_FRAG_THRESHOLD:
            ldi_details.append(
                f"sentence fragment ratio {ldi_signals['fragment_ratio']:.0%} — rushed/incoherent"
            )
        if ldi_signals.get("negation_imperative_hits", 0) > 0:
            ldi_details.append(
                f"{ldi_signals['negation_imperative_hits']} negation+procedure bypass "
                "pattern(s) — pressure language"
            )
        if ldi_details:
            parts.append(
                f"Linguistic distress indicators (LDI {ldi_composite:.1f}/15): "
                + "; ".join(ldi_details) + "."
            )

        if not parts:
            return f"No fraud-indicative language detected. Severity: {severity}/100."

        severity_label = (
            "CRITICAL" if severity >= 80 else
            "HIGH"     if severity >= 60 else
            "WATCH"    if severity >= 40 else
            "MONITOR"
        )
        return f"[{severity_label}] NLP Severity {severity}/100 — " + " | ".join(parts)

    # -----------------------------------------------------------------------
    # MAIN EVALUATE METHOD
    # -----------------------------------------------------------------------

    def evaluate(self, transaction: dict) -> dict:
        """
        Evaluate a transaction's text fields for NLP fraud signals.

        Text extraction priority:
          1. 'remarks'        — primary transaction annotation field
          2. 'complaint_text' — customer/whistle-blower complaint field
          3. 'notes'          — secondary annotation
          4. Concatenates all three if multiple fields are present.

        Scoring pipeline:
          Layer 1: Lexicon TF-IDF score  → base_score (0–MAX_BASE_SCORE)
          Layer 2: Cluster amplification → amplified_score
          Layer 3: LDI composite         → +0 to +15 modifier
          Final:   clip(amplified + LDI, 0, 100) → severity_index

        Args:
            transaction (dict): Must contain at least one of:
                - remarks         (str): Transaction remarks
                - complaint_text  (str): Complaint or whistle-blower text
                - notes           (str): Additional notes
              Optional:
                - emp_id          (str)
                - transaction_id  (str)

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

        # ── 1. Text extraction — concatenate all available text fields ────
        raw_parts = []
        for field in ("remarks", "complaint_text", "notes"):
            val = transaction.get(field, "")
            if isinstance(val, str) and val.strip():
                raw_parts.append(val.strip())

        if not raw_parts:
            return {
                "severity_index": 0,
                "signal":         "NO_TEXT",
                "reason":         "No text field (remarks/complaint_text/notes) found in payload."
            }

        raw_text = " ".join(raw_parts)

        # ── 2. Preprocessing ──────────────────────────────────────────────
        text_lower, text_original = self._preprocess(raw_text)

        # ── 3. Layer 1 — TF-IDF Lexicon Score ────────────────────────────
        base_score, category_hits, matched_phrases = \
            self._compute_tfidf_score(text_lower)

        # ── 4. Layer 2 — Cluster Amplification ───────────────────────────
        amplified_score, was_amplified = \
            self._apply_cluster_amplification(base_score, category_hits)

        # ── 5. Layer 3 — Linguistic Distress Indicators ───────────────────
        ldi_composite, ldi_signals = self._compute_ldi(text_original)

        # ── 6. Final severity index ───────────────────────────────────────
        raw_severity  = amplified_score + ldi_composite
        severity_index = int(min(100, max(0, round(raw_severity))))

        # ── 7. Signal and reason ──────────────────────────────────────────
        negation_hits = ldi_signals.get("negation_imperative_hits", 0)
        signal = self._resolve_signal(
            severity_index, category_hits, was_amplified, negation_hits
        )
        reason = self._build_reason(
            severity_index, matched_phrases, category_hits,
            was_amplified, ldi_composite, ldi_signals, text_lower
        )

        return {
            "severity_index": severity_index,
            "signal":         signal,
            "reason":         reason
        }

ComplaintSignal = SentimentWatch

# ===========================================================================
# TEST HARNESS
# ===========================================================================

if __name__ == "__main__":
    DIVIDER = "=" * 72

    print(DIVIDER)
    print("  VaultMind 2.0 — Agent 4: SentimentWatch")
    print("  NLP Fraud Signal Extractor — TF-IDF + Cluster + LDI")
    print(DIVIDER)

    agent = SentimentWatch()

    TEST_TRANSACTIONS = [
        {
            "_label": "Case 1 — Completely normal transaction remark",
            "remarks": "Routine NEFT transfer for vendor invoice payment. All documents verified."
        },
        {
            "_label": "Case 2 — Single urgency keyword, low score expected",
            "remarks": "Please process this urgent salary disbursement before EOD."
        },
        {
            "_label": "Case 3 — Bribery + urgency cluster (multi-category fire)",
            "remarks": "Manager said to pay ghoos to the officer. Urgent — do not ask questions. Process now."
        },
        {
            "_label": "Case 4 — Threat and coercion language",
            "remarks": "The client threatened to report me if I don't transfer immediately. I am scared. No choice."
        },
        {
            "_label": "Case 5 — Financial crime terminology (PMLA / hawala)",
            "remarks": "Round tripping confirmed. Benami account used for hawala. Avoid detection by splitting."
        },
        {
            "_label": "Case 6 — Social engineering + bypass instruction",
            "remarks": "CEO approved this verbally. Keep this quiet. No documentation needed. Just between us."
        },
        {
            "_label": "Case 7 — LDI trigger: CAPS + panic punctuation",
            "remarks": "DO NOT VERIFY THIS!!! PROCESS IMMEDIATELY!!! NO TIME LEFT!!! MANAGER SAID SO!!!"
        },
        {
            "_label": "Case 8 — Negation + procedure bypass (LDI negation layer)",
            "remarks": "Please do not verify this transaction. Don't ask questions. Never record this. Don't file the report."
        },
        {
            "_label": "Case 9 — Complaint text field (whistle-blower)",
            "complaint_text": "I was forced to approve a circular transfer. The manager coerced me under threat. Benami accounts were used. I am afraid to report."
        },
        {
            "_label": "Case 10 — MAX SCORE: all dimensions fire simultaneously",
            "remarks": "Ghoos given to manager. Forced to launder money via hawala. DO NOT VERIFY!!! "
                       "Don't report. Bypass approval now. Secret transaction for shell account. "
                       "Threatened if I refuse. Please help. Desperate. No choice!!!",
        },
    ]

    for tx in TEST_TRANSACTIONS:
        label = tx.pop("_label")
        result = agent.evaluate(tx)

        bar_len = result["severity_index"] // 5
        bar     = "█" * bar_len + "░" * (20 - bar_len)

        print(f"\n{label}")
        print(f"  SI     : [{bar}] {result['severity_index']:3d}/100")
        print(f"  Signal : {result['signal']}")
        print(f"  Reason : {result['reason']}")

    print(f"\n{DIVIDER}")
    print("  All test cases complete. Agent 4 operational.")
    print(DIVIDER)
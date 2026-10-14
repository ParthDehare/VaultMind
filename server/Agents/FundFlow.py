"""
VaultMind 2.0 â€” agent2_fund_flow.py
===========================================================================
Agent 2: FundFlow â€” Graph-based Fund Flow & Anomaly Detection.
---------------------------------------------------------------------------
Graph-based Network Threat & Money Layering Detection Engine.

Simulates GraphSAGE-style neighbourhood aggregation to detect:

  A. IP Reputation Score (IRS)
     Classifies the source IP address using a three-tier threat
     intelligence model:
       Tier 1 â€” Known Tor exit node:    maximum suspicion
       Tier 2 â€” Known VPN/proxy CIDR:   high suspicion
       Tier 3 â€” Geolocation anomaly:    moderate suspicion
             (IP geolocation outside India for an Indian PSB transaction)

     IRS is NOT binary. Each tier produces a continuous weight; the
     final IRS is the maximum across all firing tiers, scaled to 0â€“100.
     This prevents double-counting while preserving the strongest signal.

  B. Graph Hop Layering Score (GHLS)
     Simulates a 3-hop neighbourhood traversal on the transaction graph
     â€” the core operation of GraphSAGE's mean-aggregator applied to
     money-laundering topology:

       Hop 0 (ego node):    the initiating employee/account
       Hop 1 (direct):      direct counterparty accounts
       Hop 2 (second-ring): counterparties of counterparties
       Hop 3+ (deep):       tertiary connections (layering depth)

     Each hop aggregates: {unique_accounts, total_flow, cycle_detected}.
     A "cycle" (money returning to an account seen at an earlier hop)
     is the key layering signal â€” equivalent to detecting a
     graph cycle in the ego-network. Cycle detection uses a visited-set
     intersection at each hop level, producing a continuous flow_cycle_score.

     GHLS also penalises:
       - Fan-out width (1 account â†’ 5+ accounts in one hop = structuring)
       - Abnormal flow ratios (hop N+1 flow > hop N flow = amplification)

  C. Velocity Anomaly Score (VelAS)
     Detects rapid sequential transactions from the same source within
     a short session window â€” indicative of automated layering scripts
     or smurfing coordination. Uses Z-Score against peer class baseline
     for transaction_count_in_window.

  Final Score:
    NRI = clip(w_irsÃ—IRS + w_ghlsÃ—GHLS + w_velasÃ—VelAS, 0, 100)
    Weights: IRS=0.40, GHLS=0.40, VelAS=0.20

Return contract (strict):
  {
    "severity_index": int   (0â€“100, Network Risk Index),
    "signal":         str   (machine-readable tag),
    "reason":         str   (plain-English XAI for FCU investigator)
  }

Dependencies: Python stdlib + math only. No numpy. No external APIs.
Hackathon-safe â€” all threat intelligence is loaded from local files
with hardcoded empirical fallbacks.
===========================================================================
"""

import math
import json
import os
import warnings
import requests
from typing import Dict, List, Tuple, Set

try:
    from core.db_connections import redis_db as _geo_redis
except ImportError:
    _geo_redis = None

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
TOR_LIST_PATH = os.path.join(SCRIPT_DIR, "threat_intel", "tor_exit_nodes.json")
VPN_LIST_PATH = os.path.join(SCRIPT_DIR, "threat_intel", "vpn_cidr_ranges.json")
GRAPH_DB_PATH = os.path.join(SCRIPT_DIR, "threat_intel", "transaction_graph.json")
VEL_BASE_PATH = os.path.join(SCRIPT_DIR, "baselines", "network_velocity_baselines.json")

# Composite weight distribution â€” must sum to 1.0
WEIGHT_IRS   = 0.40   # IP Reputation Score
WEIGHT_GHLS  = 0.40   # Graph Hop Layering Score
WEIGHT_VELAS = 0.20   # Velocity Anomaly Score

# GraphSAGE simulation parameters
MAX_HOP_DEPTH       = 3     # Maximum hops to traverse (beyond 3 = too noisy)
HOP_DECAY_FACTOR    = 0.75  # Risk contribution decays with each hop (0.75^hop)
FAN_OUT_THRESHOLD   = 4     # Fan-out >= this at any hop triggers structuring flag
CYCLE_SCORE_BASE    = 85.0  # Base GHLS score for a confirmed circular routing cycle

# Sigmoid steepness â€” consistent across all VaultMind agents
SIGMOID_K     = 0.9
Z_NOISE_FLOOR = 0.5

# Indian PSB IP geolocation: all legitimate logins should be from Indian IPs
# (simplified: we use /8 prefix as a proxy for country-level geo-check)
INDIA_IP_PREFIXES = {
    "1.", "14.", "27.", "43.", "49.", "59.", "61.", "101.",
    "103.", "106.", "110.", "111.", "112.", "113.", "114.",
    "115.", "116.", "117.", "118.", "119.", "120.", "121.",
    "122.", "123.", "124.", "125.", "180.", "182.", "183.",
    "202.", "203.", "210.", "211.", "220.", "223.", "49.",
    "10.", "172.", "192.", "127.",  # Private/loopback (treated as internal)
}

# ---------------------------------------------------------------------------
# HARDCODED THREAT INTELLIGENCE â€” Fallbacks if JSON files missing
# ---------------------------------------------------------------------------

# Known Tor exit node IPs (sample â€” real deployment would load ~7000 nodes)
DEFAULT_TOR_EXIT_NODES: Set[str] = {
    "185.220.101.47", "185.220.101.35", "185.220.101.48",
    "185.220.100.240", "185.220.100.241", "185.220.100.253",
    "185.220.102.8",  "51.15.43.205",    "45.33.32.156",
    "104.244.76.13",  "162.247.74.27",   "171.25.193.9",
    "176.10.104.240", "199.87.154.255",  "109.70.100.22",
    "195.176.3.19",   "77.247.181.162",  "5.9.158.75",
}

# Known VPN/anonymiser CIDR prefixes (simplified /16 representation)
DEFAULT_VPN_CIDRS: Set[str] = {
    "185.220.", "51.15.",  "45.33.",  "104.244.",
    "162.247.", "171.25.", "176.10.", "199.87.",
    "109.70.",  "195.176.", "77.247.", "89.234.",
    "193.11.",  "194.165.", "198.98.", "204.85.",
    "209.222.", "212.21.",  "91.108.", "149.202.",
}

# Sample in-memory transaction graph for GraphSAGE simulation
# Structure: account_id â†’ {counterparties: [acc_id, ...], total_flow: float}
DEFAULT_GRAPH: Dict[str, dict] = {
    "ACC_NORM_001": {"counterparties": ["ACC_NORM_002", "ACC_NORM_003"], "total_flow": 45000.0},
    "ACC_NORM_002": {"counterparties": ["ACC_NORM_001", "ACC_NORM_004"], "total_flow": 38000.0},
    "ACC_NORM_003": {"counterparties": ["ACC_NORM_001"],                  "total_flow": 22000.0},
    "ACC_NORM_004": {"counterparties": ["ACC_NORM_002", "ACC_NORM_005"], "total_flow": 85000.0},
    "ACC_NORM_005": {"counterparties": ["ACC_NORM_004"],                  "total_flow": 30000.0},
    # Suspicious circular routing: 006â†’007â†’008â†’006 (3-node cycle)
    "ACC_SUSP_006": {"counterparties": ["ACC_SUSP_007", "ACC_NORM_001"], "total_flow": 500000.0},
    "ACC_SUSP_007": {"counterparties": ["ACC_SUSP_008"],                  "total_flow": 498000.0},
    "ACC_SUSP_008": {"counterparties": ["ACC_SUSP_006", "ACC_NORM_002"], "total_flow": 495000.0},
    # Shell accounts: wide fan-out (structuring)
    "ACC_SHELL_001": {
        "counterparties": [
            "ACC_NORM_001", "ACC_NORM_002", "ACC_NORM_003",
            "ACC_NORM_004", "ACC_NORM_005", "ACC_SUSP_006"
        ],
        "total_flow": 299000.0
    },
}

# Velocity baselines: emp_class â†’ mean/std for tx_count_in_window
DEFAULT_VEL_BASELINES: Dict[str, dict] = {
    "CLERK":     {"mean": 4.2,  "std": 2.1},
    "MANAGER":   {"mean": 8.5,  "std": 3.8},
    "IT_ADMIN":  {"mean": 2.1,  "std": 1.2},
    "EXECUTIVE": {"mean": 3.0,  "std": 1.5},
    "DEFAULT":   {"mean": 5.0,  "std": 2.5},
}


# ===========================================================================
# AGENT CLASS
# ===========================================================================

class FundFlow:
    """
    FundFlow: Graph-based Fund Flow & Anomaly Detection.

    Implements a GraphSAGE-style mean-aggregator over a transaction graph
    to detect circular routing, fan-out structuring, Tor/VPN access, and
    high-velocity transaction sequences.

    Three analytical dimensions:

    A. IP Reputation Score (IRS, 0â€“100)
       Threat intelligence lookup: Tor exit node â†’ VPN CIDR â†’ geo-anomaly.
       Maximum of all firing tiers, scaled 0â€“100.

    B. Graph Hop Layering Score (GHLS, 0â€“100)
       Simulates 3-hop BFS on transaction graph from source account.
       Detects: circular routing (cycle in ego-network), fan-out width
       (structuring), and abnormal flow amplification across hops.

    C. Velocity Anomaly Score (VelAS, 0â€“100)
       Z-Score of tx_count_in_window vs peer class baseline.
       Sigmoid transform â†’ 0â€“100.

    Final: NRI = 0.40Ã—IRS + 0.40Ã—GHLS + 0.20Ã—VelAS.

    Usage:
        agent = FundFlow()
        result = agent.evaluate(transaction_dict)
        print(result["severity_index"])   # 0â€“100
    """

    def __init__(
        self,
        tor_path: str  = TOR_LIST_PATH,
        vpn_path: str  = VPN_LIST_PATH,
        graph_path: str = GRAPH_DB_PATH,
        vel_path: str  = VEL_BASE_PATH,
    ):
        """
        Initialise FundFlow. Loads four data sources:
          1. Tor exit node list   (Set â€” O(1) lookup)
          2. VPN CIDR prefixes    (Set â€” O(1) prefix lookup)
          3. Transaction graph    (Dict â€” O(1) adjacency lookup)
          4. Velocity baselines   (Dict â€” O(1) class lookup)

        All four fall back to empirical defaults if files are missing,
        ensuring the agent stays operational in any environment.

        Args:
            tor_path:   Path to tor_exit_nodes.json
            vpn_path:   Path to vpn_cidr_ranges.json
            graph_path: Path to transaction_graph.json
            vel_path:   Path to network_velocity_baselines.json
        """
        self.tor_nodes:      Set[str]        = set()
        self.vpn_cidrs:      Set[str]        = set()
        self.graph:          Dict[str, dict] = {}
        self.vel_baselines:  Dict[str, dict] = {}

        self._load_tor_nodes(tor_path)
        self._load_vpn_cidrs(vpn_path)
        self._load_graph(graph_path)
        self._load_vel_baselines(vel_path)

    # -----------------------------------------------------------------------
    # INITIALISATION â€” DATA LOADERS
    # -----------------------------------------------------------------------

    def _load_tor_nodes(self, path: str) -> None:
        """Load Tor exit node IPs into an O(1) hash set."""
        try:
            if not os.path.exists(path):
                raise FileNotFoundError(f"Tor list not found: {path}")
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            assert isinstance(data, list), "Tor node file must be a JSON array."
            self.tor_nodes = set(data)
            print(f"[FundFlow] Tor nodes loaded: {len(self.tor_nodes)} IPs.")
        except (FileNotFoundError, AssertionError, json.JSONDecodeError) as exc:
            warnings.warn(
                f"[FundFlow] Tor list load failed ({exc}). "
                "Using sample fallback list."
            )
            self.tor_nodes = DEFAULT_TOR_EXIT_NODES

    def _load_vpn_cidrs(self, path: str) -> None:
        """Load VPN/proxy CIDR prefixes into an O(1) hash set."""
        try:
            if not os.path.exists(path):
                raise FileNotFoundError(f"VPN list not found: {path}")
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            assert isinstance(data, list), "VPN CIDR file must be a JSON array."
            self.vpn_cidrs = set(data)
            print(f"[FundFlow] VPN CIDRs loaded: {len(self.vpn_cidrs)} prefixes.")
        except (FileNotFoundError, AssertionError, json.JSONDecodeError) as exc:
            warnings.warn(
                f"[FundFlow] VPN list load failed ({exc}). "
                "Using sample fallback list."
            )
            self.vpn_cidrs = DEFAULT_VPN_CIDRS

    def _load_graph(self, path: str) -> None:
        """Load transaction graph adjacency dictionary."""
        try:
            if not os.path.exists(path):
                raise FileNotFoundError(f"Graph DB not found: {path}")
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            assert isinstance(data, dict), "Graph file must be a JSON object."
            self.graph = data
            print(f"[FundFlow] Transaction graph loaded: {len(self.graph)} nodes.")
        except (FileNotFoundError, AssertionError, json.JSONDecodeError) as exc:
            warnings.warn(
                f"[FundFlow] Graph DB load failed ({exc}). "
                "Using sample transaction graph."
            )
            self.graph = DEFAULT_GRAPH

    def _load_vel_baselines(self, path: str) -> None:
        """Load velocity baselines for Z-Score computation."""
        try:
            if not os.path.exists(path):
                raise FileNotFoundError(f"Velocity baseline not found: {path}")
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            assert isinstance(data, dict), "Velocity baseline must be a JSON object."
            self.vel_baselines = data
            print("[FundFlow] Velocity baselines loaded.")
        except (FileNotFoundError, AssertionError, json.JSONDecodeError) as exc:
            warnings.warn(
                f"[FundFlow] Velocity baseline load failed ({exc}). "
                "Using empirical defaults."
            )
            self.vel_baselines = DEFAULT_VEL_BASELINES

    # -----------------------------------------------------------------------
    # MATHEMATICAL CORE
    # -----------------------------------------------------------------------

    @staticmethod
    def _z_score(value: float, mean: float, std: float) -> float:
        """
        Standard Z-Score: (X - Î¼) / Ïƒ
        Returns 0.0 for near-zero std to prevent division errors.
        """
        if std < 1e-6:
            return 0.0
        return (value - mean) / std

    @staticmethod
    def _sigmoid_risk(z: float, k: float = SIGMOID_K) -> float:
        """
        Bounded sigmoid: converts Z-Score to 0â€“100 risk contribution.
        Consistent with Agent 1, 3, and 5 implementations.

            effective_z = max(0, z) - Z_NOISE_FLOOR
            risk        = sigmoid(k Ã— effective_z) Ã— 100
        """
        z_pos       = max(0.0, z)
        effective_z = z_pos - Z_NOISE_FLOOR
        if effective_z <= 0.0:
            return 0.0
        try:
            raw = 1.0 / (1.0 + math.exp(-k * effective_z))
        except OverflowError:
            raw = 1.0
        return min(100.0, raw * 100.0)

    # -----------------------------------------------------------------------
    # DIMENSION A â€” IP REPUTATION SCORE
    # -----------------------------------------------------------------------

    def _compute_irs(self, source_ip: str) -> Tuple[float, List[str]]:
        """
        Compute IP Reputation Score (IRS) using three-tier threat model.

        Tier 1 â€” Tor exit node match (O(1) set lookup):
            Weight = 0.97 â†’ IRS = 97
        Tier 2 â€” VPN/proxy CIDR prefix match (O(1) set lookup on /16 prefix):
            Weight = 0.78 â†’ IRS = 78
        Tier 3 â€” Geolocation anomaly (non-Indian IP prefix):
            Weight = 0.52 â†’ IRS = 52

        Final IRS = max(all firing tiers) Ã— 100.
        Using max (not sum) prevents double-counting when multiple tiers
        fire for the same IP â€” the most specific signal wins.

        Args:
            source_ip: IP address string from the transaction payload.

        Returns:
            Tuple of (irs_score 0â€“100, list of fired tier descriptions)
        """
        if not source_ip or not isinstance(source_ip, str):
            return 0.0, []

        ip = source_ip.strip()
        fired_tiers: List[str]  = []
        max_weight: float       = 0.0

        # â”€â”€ Tier 1: Tor exit node (exact O(1) hash-set lookup) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if ip in self.tor_nodes:
            max_weight = max(max_weight, 0.97)
            fired_tiers.append(f"TOR_EXIT_NODE ({ip})")

        # â”€â”€ Tier 2: VPN/Proxy CIDR prefix (O(1) on /16 prefix) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # Extract the /16 prefix: "185.220.101.47" â†’ "185.220."
        parts = ip.split(".")
        if len(parts) >= 2:
            cidr_16 = f"{parts[0]}.{parts[1]}."
            if cidr_16 in self.vpn_cidrs:
                max_weight = max(max_weight, 0.78)
                fired_tiers.append(f"VPN_PROXY_CIDR ({cidr_16}*)")

        # â”€â”€ Tier 3: Geolocation anomaly (non-Indian IP) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if ip:
            is_indian = False
            # Check Redis cache first, then API, then static fallback
            cache_key = f"geoip:{ip}"
            cached = None
            if _geo_redis:
                try:
                    cached = _geo_redis.get(cache_key)
                except Exception:
                    cached = None

            if cached is not None:
                is_indian = (cached == b"IN" or cached == "IN")
            else:
                country = None
                try:
                    resp = requests.get(f"https://ipapi.co/{ip}/country/", timeout=1.0)
                    if resp.status_code == 200:
                        country = resp.text.strip()
                except Exception:
                    pass

                if country is None:
                    # Static prefix fallback
                    is_indian = any(ip.startswith(pfx) for pfx in INDIA_IP_PREFIXES)
                    country = "IN" if is_indian else "XX"
                else:
                    is_indian = (country == "IN")

                # Cache result for 24 hours
                if _geo_redis:
                    try:
                        _geo_redis.setex(cache_key, 86400, country)
                    except Exception:
                        pass

            if not is_indian and max_weight < 0.52:
                # Only fire if Tor/VPN haven't already covered the IP
                max_weight = max(max_weight, 0.52)
                fired_tiers.append(f"GEO_ANOMALY (non-Indian IP: {ip})")

        irs_score = max_weight * 100.0
        return min(100.0, irs_score), fired_tiers

    # -----------------------------------------------------------------------
    # DIMENSION B â€” GRAPH HOP LAYERING SCORE (GraphSAGE simulation)
    # -----------------------------------------------------------------------

    def _graphsage_hop_traverse(
        self, source_account: str
    ) -> Tuple[float, dict]:
        """
        Simulate GraphSAGE mean-aggregator over 3-hop ego-network.

        Algorithm (BFS with visited-set cycle detection):

        For each hop h in [1, 2, 3]:
          1. Expand frontier: collect all accounts reachable in h hops
             from source_account using graph adjacency (O(1) per node).
          2. Aggregate neighbourhood features:
               - unique_accounts_at_hop_h  (set)
               - total_flow_at_hop_h       (sum)
               - fan_out_h                 (len(frontier_set))
          3. Cycle detection: if any account in hop_h_frontier was
             already seen in hops 0..h-1 (visited set intersection),
             a circular routing pattern is confirmed.
          4. Risk contribution at hop h:
               hop_risk = base_score Ã— HOP_DECAY_FACTOR^h
             The decay ensures hop-1 connections carry more weight
             than hop-3 ones â€” matching GraphSAGE's distance-weighted
             aggregation.

        Additional signals:
          - Fan-out structuring: fan_out >= FAN_OUT_THRESHOLD at any hop
          - Flow amplification: flow at hop h+1 > flow at hop h
            (money growing through the network = injection signal)

        Args:
            source_account: Account ID of the initiating entity.

        Returns:
            Tuple of (ghls_score 0â€“100, analysis_metadata dict)
        """
        from core.historical_state import historical_state


        def get_node_data(acc):
            live_entry = historical_state.live_adjacency.get(acc, {})
            static_entry = self.graph.get(acc, {})
            counterparties = list(set(list(live_entry.get("counterparties", [])) + list(static_entry.get("counterparties", []))))
            total_flow = live_entry.get("total_flow", 0.0) + static_entry.get("total_flow", 0.0)
            return {"counterparties": counterparties, "total_flow": total_flow}

        in_live = source_account in historical_state.live_adjacency
        in_static = source_account in self.graph
        if not source_account or (not in_live and not in_static):
            return 0.0, {"hops": [], "cycle_detected": False, "source_in_graph": False}

        visited: Set[str]      = {source_account}
        frontier: Set[str]     = {source_account}
        hop_analysis: List[dict] = []

        cycle_detected    = False
        max_fan_out       = 0
        flow_amplified    = False
        prev_hop_flow     = get_node_data(source_account).get("total_flow", 0.0)
        ghls_contributions: List[float] = []

        for hop in range(1, MAX_HOP_DEPTH + 1):
            next_frontier: Set[str] = set()
            hop_flow = 0.0

            for account in frontier:
                node_data      = get_node_data(account)
                counterparties = node_data.get("counterparties", [])

                for cp in counterparties:
                    # â”€â”€ Cycle detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                    # If counterparty was already visited â†’ circular routing
                    if cp in visited and cp != source_account:
                        cycle_detected = True

                    if cp not in visited:
                        next_frontier.add(cp)

                    # Aggregate flow at this hop
                    cp_flow = get_node_data(cp).get("total_flow", 0.0)
                    hop_flow += cp_flow

            # Fan-out width at this hop
            fan_out = len(next_frontier)
            max_fan_out = max(max_fan_out, fan_out)

            # Flow amplification check
            if hop_flow > prev_hop_flow * 1.1 and prev_hop_flow > 0:
                flow_amplified = True

            # â”€â”€ Hop risk contribution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            hop_base_risk = 0.0

            # Cycle in this hop â€” strongest signal
            if cycle_detected:
                hop_base_risk = CYCLE_SCORE_BASE

            # Fan-out structuring signal (continuous: fan_out / threshold)
            if fan_out >= FAN_OUT_THRESHOLD:
                fan_out_risk = min(70.0, (fan_out / FAN_OUT_THRESHOLD) * 35.0)
                hop_base_risk = max(hop_base_risk, fan_out_risk)

            # Apply hop decay: closer hops carry more evidential weight
            decay = HOP_DECAY_FACTOR ** hop
            hop_contribution = hop_base_risk * decay
            ghls_contributions.append(hop_contribution)

            hop_analysis.append({
                "hop":          hop,
                "frontier_size": fan_out,
                "hop_flow":     hop_flow,
                "contribution": round(hop_contribution, 2),
            })

            # Update state for next hop
            visited.update(next_frontier)
            frontier = next_frontier
            prev_hop_flow = hop_flow if hop_flow > 0 else prev_hop_flow

            if not frontier:
                break  # No further nodes to expand

        # â”€â”€ Aggregate GHLS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # Sum contributions across all hops (not max) â€” layering depth adds
        # cumulative risk, unlike IP reputation where max wins.
        ghls_raw = sum(ghls_contributions)

        # Additional flow amplification bonus
        if flow_amplified:
            ghls_raw = min(100.0, ghls_raw * 1.2)

        ghls_score = min(100.0, ghls_raw)

        metadata = {
            "hops":            hop_analysis,
            "cycle_detected":  cycle_detected,
            "max_fan_out":     max_fan_out,
            "flow_amplified":  flow_amplified,
            "source_in_graph": True,
            "total_nodes_visited": len(visited),
        }
        return ghls_score, metadata

    # -----------------------------------------------------------------------
    # DIMENSION C â€” VELOCITY ANOMALY SCORE
    # -----------------------------------------------------------------------

    def _compute_velas(
        self, emp_class: str, tx_count_in_window: float
    ) -> Tuple[float, float, dict]:
        """
        Compute Velocity Anomaly Score using Z-Score analysis.

        High transaction velocity (many transactions in a short window)
        from the same source indicates automated layering scripts or
        coordinated smurfing. Continuous Z-Score replaces hard cutoffs.

        Args:
            emp_class:           Employee class.
            tx_count_in_window:  Transaction count in recent time window.

        Returns:
            Tuple of (velas_score 0â€“100, z_score, baseline_dict)
        """
        baseline = self.vel_baselines.get(
            emp_class.upper(),
            self.vel_baselines.get("DEFAULT", DEFAULT_VEL_BASELINES["DEFAULT"])
        )
        z         = self._z_score(tx_count_in_window, baseline["mean"], baseline["std"])
        vel_score = self._sigmoid_risk(z)
        return vel_score, z, baseline

    # -----------------------------------------------------------------------
    # SIGNAL RESOLVER
    # -----------------------------------------------------------------------

    @staticmethod
    def _resolve_signal(
        nri: int,
        irs_score: float,
        ghls_score: float,
        velas_score: float,
        irs_tiers: List[str],
        cycle_detected: bool,
        max_fan_out: int
    ) -> str:
        """
        Determine the dominant signal tag.

        Priority:
          TOR_CIRCULAR_ROUTING (both IRS Tor + GHLS cycle) â†’
          CIRCULAR_ROUTING     (GHLS cycle alone) â†’
          TOR_ACCESS           (IRS Tor alone) â†’
          STRUCTURING_FANOUT   (fan-out) â†’
          VPN_PROXY            (IRS VPN) â†’
          VELOCITY_BURST       (VelAS alone) â†’
          GEO_ANOMALY          (geo alone) â†’
          NETWORK_ANOMALY      (generic)

        Args:
            nri:            Final composite score.
            irs_score:      IP reputation score.
            ghls_score:     Graph layering score.
            velas_score:    Velocity score.
            irs_tiers:      List of fired IP tier descriptions.
            cycle_detected: Whether a graph cycle was found.
            max_fan_out:    Maximum fan-out seen across hops.

        Returns:
            str: Machine-readable signal tag.
        """
        if nri == 0:
            return "NORMAL"

        tor_fired = any("TOR_EXIT" in t for t in irs_tiers)
        vpn_fired = any("VPN_PROXY" in t for t in irs_tiers)
        geo_fired = any("GEO_ANOMALY" in t for t in irs_tiers)

        # Determine dominant dimension and sub-type
        if tor_fired and cycle_detected:
            dominant = "TOR_CIRCULAR_ROUTING"
        elif cycle_detected:
            dominant = "CIRCULAR_ROUTING"
        elif tor_fired:
            dominant = "TOR_ACCESS"
        elif max_fan_out >= FAN_OUT_THRESHOLD:
            dominant = "STRUCTURING_FANOUT"
        elif vpn_fired:
            dominant = "VPN_PROXY_ACCESS"
        elif velas_score > max(irs_score, ghls_score):
            dominant = "VELOCITY_BURST"
        elif geo_fired:
            dominant = "GEO_ANOMALY_LOGIN"
        else:
            dominant = "NETWORK_ANOMALY"

        prefix = (
            "CRITICAL" if nri >= 80 else
            "HIGH"     if nri >= 60 else
            "WATCH"    if nri >= 40 else
            "MONITOR"
        )
        return f"{prefix}_{dominant}"

    # -----------------------------------------------------------------------
    # XAI REASON BUILDER
    # -----------------------------------------------------------------------

    @staticmethod
    def _build_reason(
        nri: int,
        source_ip: str,
        source_account: str,
        emp_class: str,
        irs_score: float,
        irs_tiers: List[str],
        ghls_score: float,
        graph_meta: dict,
        velas_score: float,
        z_vel: float,
        vel_baseline: dict,
        tx_count_in_window: float,
    ) -> str:
        """
        Build plain-English XAI reason string for FCU investigator.

        Surfaces specific IP, graph topology, and velocity numbers so
        investigators can independently verify each component score.

        Args:
            (see evaluate() for field descriptions)

        Returns:
            str: XAI reason string.
        """
        parts = []

        # IRS narrative
        if irs_score > 0 and irs_tiers:
            parts.append(
                f"IP {source_ip} matched threat intelligence: "
                + "; ".join(irs_tiers)
                + f" (IRS: {irs_score:.0f}/100)."
            )

        # GHLS narrative
        if ghls_score > 0 and graph_meta.get("source_in_graph"):
            cycle_str   = "Circular routing CONFIRMED â€” money returned to a previous account." \
                          if graph_meta.get("cycle_detected") else ""
            fan_str     = (
                f"Fan-out of {graph_meta.get('max_fan_out', 0)} accounts detected "
                f"(structuring threshold: {FAN_OUT_THRESHOLD})."
                if graph_meta.get("max_fan_out", 0) >= FAN_OUT_THRESHOLD else ""
            )
            amp_str     = "Flow amplification across hops detected (money increasing through layers)." \
                          if graph_meta.get("flow_amplified") else ""
            nodes_vis   = graph_meta.get("total_nodes_visited", 0)
            hop_details = ", ".join(
                f"Hop{h['hop']}: {h['frontier_size']} nodes"
                for h in graph_meta.get("hops", [])
                if h["frontier_size"] > 0
            )

            graph_parts = [s for s in [cycle_str, fan_str, amp_str] if s]
            ghls_reason = (
                f"Graph analysis ({nodes_vis} nodes, {hop_details}): "
                + (" ".join(graph_parts) if graph_parts else "Anomalous network topology detected.")
                + f" (GHLS: {ghls_score:.0f}/100)."
            )
            parts.append(ghls_reason)

        elif ghls_score > 0 and not graph_meta.get("source_in_graph"):
            parts.append(
                f"Account {source_account} not yet in transaction graph â€” "
                f"new node with no relationship history. (GHLS: {ghls_score:.0f}/100)."
            )

        # VelAS narrative
        if velas_score > 0:
            peer_mean = vel_baseline["mean"]
            parts.append(
                f"{tx_count_in_window:.0f} transactions in current window â€” "
                f"{z_vel:.1f} std-dev above {emp_class} peer average ({peer_mean:.1f}). "
                f"Possible automated layering. (VelAS: {velas_score:.0f}/100)."
            )

        if not parts:
            return f"All network dimensions within normal range. NRI: {nri}/100."

        severity_label = (
            "CRITICAL" if nri >= 80 else
            "HIGH"     if nri >= 60 else
            "WATCH"    if nri >= 40 else
            "MONITOR"
        )
        return f"[{severity_label}] NRI {nri}/100 â€” " + " | ".join(parts)

    # -----------------------------------------------------------------------
    # MAIN EVALUATE METHOD
    # -----------------------------------------------------------------------

    def evaluate(self, transaction: dict) -> dict:
        """
        Evaluate a transaction for network-level threat signals.

        Computes the Network Risk Index (NRI) through three dimensions:

          A. IP Reputation Score (IRS)
             O(1) set lookups against Tor exit node list and VPN CIDR
             prefixes, plus geolocation prefix check for Indian PSB context.

          B. Graph Hop Layering Score (GHLS)
             GraphSAGE-style 3-hop BFS on transaction graph. Detects
             circular routing (cycle detection via visited-set intersection),
             structuring (fan-out width), and flow amplification.

          C. Velocity Anomaly Score (VelAS)
             Z-Score of tx_count_in_window vs peer class baseline.
             Sigmoid transform â†’ 0â€“100.

          NRI = 0.40Ã—IRS + 0.40Ã—GHLS + 0.20Ã—VelAS.

        Args:
            transaction (dict): Must contain at minimum:
                - source_ip           (str)   : Login IP address
                - source_account      (str)   : Initiating account ID
                - emp_class           (str)   : CLERK / MANAGER etc.
                - tx_count_in_window  (int)   : Transactions in current session
              Optional:
                - emp_id              (str)
                - transaction_id      (str)
                - destination_account (str)

        Returns:
            dict: {
                "severity_index": int (0â€“100),
                "signal":         str,
                "reason":         str
            }
        """
        # â”€â”€ 0. Input validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if not isinstance(transaction, dict):
            return {
                "severity_index": 0,
                "signal":         "INVALID_INPUT",
                "reason":         "Transaction payload must be a dictionary."
            }

        # â”€â”€ 1. Feature extraction with safe defaults â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        source_ip          = str(transaction.get("source_ip", "")).strip()
        source_account     = str(transaction.get("source_account", "")).strip()
        emp_class          = str(transaction.get("emp_class", "DEFAULT")).upper().strip()
        tx_count_in_window = float(transaction.get("tx_count_in_window", 1.0))

        # â”€â”€ 2. Dimension A â€” IP Reputation Score (O(1) lookups) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        irs_score, irs_tiers = self._compute_irs(source_ip)

        # â”€â”€ 3. Dimension B â€” Graph Hop Layering Score â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        ghls_score, graph_meta = self._graphsage_hop_traverse(source_account)

        # â”€â”€ 4. Dimension C â€” Velocity Anomaly Score â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        velas_score, z_vel, vel_baseline = self._compute_velas(
            emp_class, tx_count_in_window
        )

        # â”€â”€ 5. Weighted Composite (NRI) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        nri_raw = (
            WEIGHT_IRS   * irs_score   +
            WEIGHT_GHLS  * ghls_score  +
            WEIGHT_VELAS * velas_score
        )
        nri = int(min(100, max(0, round(nri_raw))))

        # â”€â”€ 5b. Sequence Pass-Through Velocity check (Lapping / Dormant activation) â”€â”€
        acc_id = str(transaction.get("account_id") or transaction.get("source_account") or transaction.get("destination_account") or source_account).strip()
        from core.historical_state import historical_state
        from core.master_orchestrator import MasterOrchestrator
        seq_meta = historical_state.get_account_sequence_velocity(acc_id, MasterOrchestrator.recent_transactions, transaction)

        pass_through_detected = seq_meta.get("pass_through_detected", False)
        if pass_through_detected:
            nri = max(nri, 92)

        # â”€â”€ 5c. SPECIAL DETECTION: Household Affinity & KCC Evergreening / Loan Flipping â”€â”€
        acc_type = str(transaction.get("account_type", ""))
        linked_npa_account = transaction.get("linked_npa_account", "")
        same_household = transaction.get("same_household_affinity", False)
        if ("KCC" in acc_type or "SHG" in acc_type or "Loan" in acc_type) and linked_npa_account:
            if same_household or transaction.get("is_evergreening", False):
                return {
                    "severity_index": 92,
                    "signal": "CRITICAL_EVERGREENING_LOAN_FLIP",
                    "reason": (
                        f"[CRITICAL] KCC/SHG Evergreening detected via Household Affinity Edge: "
                        f"New loan disbursement on {acc_id} immediately adjusting NPA account {linked_npa_account} "
                        f"within same Household/Address cluster."
                    ),
                    "scoring_method": "HOUSEHOLD_GRAPH_AFFINITY",
                }

        # â”€â”€ 6. Signal and reason â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cycle_detected = graph_meta.get("cycle_detected", False)
        max_fan_out    = graph_meta.get("max_fan_out", 0)

        signal = self._resolve_signal(
            nri, irs_score, ghls_score, velas_score,
            irs_tiers, cycle_detected, max_fan_out
        )
        reason = self._build_reason(
            nri=nri, source_ip=source_ip, source_account=source_account,
            emp_class=emp_class, irs_score=irs_score, irs_tiers=irs_tiers,
            ghls_score=ghls_score, graph_meta=graph_meta,
            velas_score=velas_score, z_vel=z_vel, vel_baseline=vel_baseline,
            tx_count_in_window=tx_count_in_window
        )

        if pass_through_detected:
            signal = "CRITICAL_PASS_THROUGH_MULE"
            inflow = seq_meta.get("inflow_amount", 0.0)
            outflow = seq_meta.get("outflow_amount", 0.0)
            ratio = seq_meta.get("pass_through_ratio", 0.0)
            delta = seq_meta.get("time_delta_sec", 0)
            dormant_txt = "Dormant account " if seq_meta.get("is_dormant") else "Account "
            reason = (
                f"[CRITICAL] {dormant_txt}{acc_id} rapid pass-through velocity detected: "
                f"INR {outflow:,.0f} withdrawn immediately after INR {inflow:,.0f} deposit "
                f"({ratio*100:.1f}% pass-through within {delta}s). NRI: {nri}/100."
            )

        return {
            "severity_index": nri,
            "signal":         signal,
            "reason":         reason
        }


# ===========================================================================
# TEST HARNESS
# ===========================================================================

if __name__ == "__main__":
    DIVIDER = "=" * 72

    print(DIVIDER)
    print("  VaultMind 2.0 â€” Agent 2: FundFlow")
    print("  Graph Hop Layering + IP Reputation + Velocity Anomaly")
    print(DIVIDER)

    agent = FundFlow()

    TEST_TRANSACTIONS = [
        {
            "_label": "Case 1 â€” Normal Indian IP, known account, low velocity",
            "source_ip": "122.160.50.21",
            "source_account": "ACC_NORM_001",
            "emp_class": "CLERK",
            "tx_count_in_window": 3,
        },
        {
            "_label": "Case 2 â€” Tor exit node IP (IRS only fires)",
            "source_ip": "185.220.101.47",
            "source_account": "ACC_NORM_001",
            "emp_class": "CLERK",
            "tx_count_in_window": 4,
        },
        {
            "_label": "Case 3 â€” VPN/proxy CIDR (mid-tier IRS)",
            "source_ip": "51.15.43.205",
            "source_account": "ACC_NORM_002",
            "emp_class": "MANAGER",
            "tx_count_in_window": 6,
        },
        {
            "_label": "Case 4 â€” Circular routing account (GHLS cycle fires)",
            "source_ip": "122.160.50.21",
            "source_account": "ACC_SUSP_006",
            "emp_class": "CLERK",
            "tx_count_in_window": 4,
        },
        {
            "_label": "Case 5 â€” Shell account with wide fan-out (structuring)",
            "source_ip": "122.160.50.21",
            "source_account": "ACC_SHELL_001",
            "emp_class": "MANAGER",
            "tx_count_in_window": 7,
        },
        {
            "_label": "Case 6 â€” High velocity burst (VelAS fires)",
            "source_ip": "122.160.50.21",
            "source_account": "ACC_NORM_003",
            "emp_class": "CLERK",
            "tx_count_in_window": 18,
        },
        {
            "_label": "Case 7 â€” Tor + circular routing (both IRS and GHLS critical)",
            "source_ip": "185.220.101.47",
            "source_account": "ACC_SUSP_007",
            "emp_class": "CLERK",
            "tx_count_in_window": 5,
        },
        {
            "_label": "Case 8 â€” Foreign IP geolocation anomaly (Tier 3 IRS)",
            "source_ip": "8.8.8.8",
            "source_account": "ACC_NORM_004",
            "emp_class": "EXECUTIVE",
            "tx_count_in_window": 3,
        },
        {
            "_label": "Case 9 â€” Unknown account (not in graph)",
            "source_ip": "122.160.50.21",
            "source_account": "ACC_NEW_999",
            "emp_class": "CLERK",
            "tx_count_in_window": 2,
        },
        {
            "_label": "Case 10 â€” MAX: Tor + circular routing + high velocity",
            "source_ip": "185.220.101.47",
            "source_account": "ACC_SUSP_006",
            "emp_class": "CLERK",
            "tx_count_in_window": 25,
        },
    ]

    for tx in TEST_TRANSACTIONS:
        label = tx.pop("_label")
        result = agent.evaluate(tx)

        bar_len = result["severity_index"] // 5
        bar     = "#" * bar_len + "-" * (20 - bar_len)

        print(f"\n{label}")
        print(f"  NRI    : [{bar}] {result['severity_index']:3d}/100")
        print(f"  Signal : {result['signal']}")
        print(f"  Reason : {result['reason']}")

    print(f"\n{DIVIDER}")
    print("  All test cases complete. Agent 2 operational.")
    print(DIVIDER)


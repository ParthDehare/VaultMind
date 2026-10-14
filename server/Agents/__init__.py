# VaultMind 2.0 - Agents Initialization
# Automatically exposes all 8 agents according to the official Architecture Doc

from .BehaviourWatch import BehaviourWatch     # A1: LSTM + Isolation Forest
from .FundFlow import FundFlow                 # A2: GNN + NetworkX
from .VendorGuard import VendorGuard           # A3: API Sequence Analytics
from .ComplaintSignal import ComplaintSignal   # A4: NLP + Gemini API
from .NetworkIntel import NetworkIntel         # A5: GNN + Louvain
from .RegulatoryAI import RegulatoryAI         # A6: RAG + RBI Corpus
from .EvidenceBuilder import EvidenceBuilder   # A7: SHA-256 + Hyperledger
from .DeceptionGuard import DeceptionGuard     # A8: Honeypot

__all__ = [
    "BehaviourWatch",
    "FundFlow",
    "VendorGuard",
    "ComplaintSignal",
    "NetworkIntel",
    "RegulatoryAI",
    "EvidenceBuilder",
    "DeceptionGuard"
]
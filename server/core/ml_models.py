"""
VaultMind - ML Model Loader
Loads and caches trained models from server/models/ at startup.

FIXED:
  - Agent 1: iso_forest â†’ xgb_model, decision_function â†’ predict_proba
  - GNN architecture updated to match upgraded train_agent2.py
    (in_channels=3, hidden=64, dropout, BatchNorm)
  - optimal_threshold loaded from account_mapping.pkl and used at inference
"""
import os
import pickle
import warnings
import joblib

# Silence Scikit-Learn warnings about missing feature names in NumPy arrays
warnings.filterwarnings("ignore", category=UserWarning, message="X does not have valid feature names")

import numpy as np

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    warnings.warn("[MLModels] PyTorch not found. GNN predictions will gracefully fall back to rule engine.")

# ---------------------------------------------------------
# PyTorch Geometric GNN Architecture
# MUST match train_agent2.py exactly - hidden=64, dropout,
# BatchNorm, in_channels=3 (degree + fraud_rate node feats)
# ---------------------------------------------------------
if TORCH_AVAILABLE:
    try:
        from torch_geometric.nn import SAGEConv
        PYGEOMETRIC_AVAILABLE = True
        print("[MLModels] [OK] torch_geometric available - using real SAGEConv.")
    except ImportError:
        PYGEOMETRIC_AVAILABLE = False
        warnings.warn("[MLModels] torch_geometric not found. Using approximate GNN (linear fallback).")

        class SAGEConv(nn.Module):
            """Fallback: Linear approximation when torch_geometric is unavailable."""
            def __init__(self, in_channels, out_channels):
                super().__init__()
                self.lin_l = nn.Linear(in_channels, out_channels, bias=True)
                self.lin_r = nn.Linear(in_channels, out_channels, bias=False)
            def forward(self, x, edge_index=None):
                return self.lin_l(x)

    class GraphSAGEEdgeClassifier(nn.Module):
        """
        UPGRADED - must match train_agent2.py exactly:
          - in_channels=3  (out_degree, in_degree, fraud_rate)
          - hidden=64
          - Dropout + BatchNorm in MLP
        """
        def __init__(self, in_channels=3, hidden_channels=64, edge_in_channels=2, dropout=0.3):
            super(GraphSAGEEdgeClassifier, self).__init__()
            self.dropout = dropout
            self.conv1 = SAGEConv(in_channels, hidden_channels)
            self.conv2 = SAGEConv(hidden_channels, hidden_channels)

            mlp_in = hidden_channels * 2 + edge_in_channels
            self.edge_mlp = nn.Sequential(
                nn.Linear(mlp_in, hidden_channels),
                nn.BatchNorm1d(hidden_channels),
                nn.ReLU(),
                nn.Dropout(p=dropout),
                nn.Linear(hidden_channels, hidden_channels // 2),
                nn.ReLU(),
                nn.Linear(hidden_channels // 2, 1)
            )

        def forward(self, x, edge_index, edge_attr):
            h = self.conv1(x, edge_index)
            h = torch.relu(h)
            h = torch.nn.functional.dropout(h, p=self.dropout, training=self.training)
            h = self.conv2(h, edge_index)
            h = torch.relu(h)
            src, dst = edge_index
            edge_repr = torch.cat([h[src], h[dst], edge_attr], dim=1)
            return self.edge_mlp(edge_repr).squeeze(-1)


MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")


class MLModelService:
    """Singleton-style ML model loader. Call load_all() at startup."""

    def __init__(self):
        self.xgb_model         = None   # XGBoost classifier (Agent 1) - RENAMED from iso_forest
        self.scaler            = None   # StandardScaler (Agent 1)
        self.account_mapping   = None   # Account â†’ node index dict
        self.edge_scaler       = None   # Edge scaler for GNN
        self.optimal_threshold = 0.5    # Saved threshold from train_agent2
        self.gnn               = None   # GNN model (Agent 2)
        self._loaded           = False

    def load_all(self):
        """Load all models from disk. Call once at server startup."""
        if self._loaded:
            return

        # --- Agent 1: XGBoost + Scaler ---
        # File is still named agent1_iso_forest.pkl (no rename needed)
        model_path  = os.path.join(MODELS_DIR, "agent1_iso_forest.pkl")
        scaler_path = os.path.join(MODELS_DIR, "agent1_scaler.pkl")

        try:
            with open(model_path, "rb") as f:
                self.xgb_model = joblib.load(f)
            print(f"[MLModels] [OK] Loaded XGBoost model from {model_path}")
        except Exception as e:
            warnings.warn(f"[MLModels] [X] Failed to load XGBoost model: {e}")

        try:
            with open(scaler_path, "rb") as f:
                self.scaler = joblib.load(f)
            print(f"[MLModels] [OK] Loaded Scaler from {scaler_path}")
        except Exception as e:
            warnings.warn(f"[MLModels] [X] Failed to load Scaler: {e}")

        # --- Agent 2: Account Mapping + GNN threshold ---
        mapping_path = os.path.join(MODELS_DIR, "account_mapping.pkl")
        try:
            with open(mapping_path, "rb") as f:
                data = joblib.load(f)
            self.account_mapping   = data["account_mapping"]
            self.edge_scaler       = data["edge_scaler"]
            # Load optimal threshold saved during training (default 0.5 if missing)
            self.optimal_threshold = data.get("optimal_threshold", 0.5)
            print(
                f"[MLModels] [OK] Loaded Account Mapping "
                f"({len(self.account_mapping)} entries), "
                f"threshold={self.optimal_threshold:.2f}"
            )
        except Exception as e:
            warnings.warn(f"[MLModels] [X] Failed to load Account Mapping: {e}")

        # --- Agent 2: PyTorch GNN ---
        gnn_path = os.path.join(MODELS_DIR, "agent2_gnn.pth")
        if TORCH_AVAILABLE:
            try:
                # in_channels=3 matches upgraded train_agent2.py node features
                self.gnn = GraphSAGEEdgeClassifier(
                    in_channels=3, hidden_channels=64,
                    edge_in_channels=2, dropout=0.3
                )
                state_dict = torch.load(
                    gnn_path,
                    map_location=torch.device("cpu"),
                    weights_only=True
                )
                self.gnn.load_state_dict(state_dict, strict=True)
                self.gnn.eval()
                print(f"[MLModels] [OK] Loaded PyTorch GNN from {gnn_path}")
            except Exception as e:
                self.gnn = None
                warnings.warn(f"[MLModels] [X] Failed to load PyTorch GNN: {e}")
        else:
            self.gnn = None

        self._loaded = True

    # ------------------------------------------------------------------
    # Agent 1 - XGBoost inference
    # ------------------------------------------------------------------

    def predict_anomaly(self, features: np.ndarray) -> float:
        """
        Run XGBoost fraud prediction.

        Args:
            features: 1D numpy array - must be 7 values in this order:
                [amount, dwell_time_seconds, records_accessed, login_hour,
                 amount_vs_user_avg, time_since_last_txn, txn_count_1hr]

        Returns:
            Anomaly score 0â€“100 (higher = more likely fraud), or -1 if unavailable.
        """
        if self.xgb_model is None or self.scaler is None:
            return -1   # Fall back to rule engine

        features_2d = features.reshape(1, -1)
        scaled      = self.scaler.transform(features_2d)

        # XGBoost: predict_proba returns [[prob_normal, prob_fraud]]
        fraud_prob  = self.xgb_model.predict_proba(scaled)[0][1]

        # Convert 0â€“1 probability â†’ 0â€“100 score
        return float(min(100.0, max(0.0, fraud_prob * 100.0)))

    # ------------------------------------------------------------------
    # Agent 2 - GNN inference
    # ------------------------------------------------------------------

    def predict_gnn(self, transaction: dict) -> float:
        """
        Run PyTorch GNN prediction for NetworkIntel.

        Args:
            transaction: dict with transaction details.

        Returns:
            Network threat score 0â€“100, or -1 if unavailable.
        """
        if (self.gnn is None or self.account_mapping is None
                or self.edge_scaler is None or not TORCH_AVAILABLE):
            return -1

        emp_id = transaction.get("emp_id", "UNKNOWN")
        amt_val = transaction.get("amount")
        amt = float(amt_val) if amt_val is not None else 0.0

        dwell_val = transaction.get("dwell_time_seconds")
        dwell = float(dwell_val) if dwell_val is not None else 30.0

        # Inductive Runtime Node Enrollment: Register dynamic accounts/entities on the fly
        if self.account_mapping is None:
            self.account_mapping = {}

        src_acc = str(transaction.get("account_id") or transaction.get("source_account") or emp_id or "UNKNOWN")
        dst_acc = str(transaction.get("destination_account") or "UNKNOWN")

        if src_acc != "UNKNOWN" and src_acc not in self.account_mapping:
            self.account_mapping[src_acc] = len(self.account_mapping)
        if dst_acc != "UNKNOWN" and dst_acc not in self.account_mapping:
            self.account_mapping[dst_acc] = len(self.account_mapping)
        if emp_id != "UNKNOWN" and emp_id not in self.account_mapping:
            self.account_mapping[emp_id] = len(self.account_mapping)

        try:
            # Node features: 3 dims to match upgraded model (out_deg, in_deg, dormancy_factor)
            from core.historical_state import historical_state
            src_acc = str(transaction.get("account_id") or transaction.get("source_account") or "UNKNOWN")
            dst_acc = str(transaction.get("destination_account") or "UNKNOWN")
            src_vec = historical_state.get_node_feature_vector(src_acc, transaction)
            dst_vec = historical_state.get_node_feature_vector(dst_acc, transaction)
            x = torch.tensor([src_vec, dst_vec], dtype=torch.float32)   # shape (2 nodes, 3 features)

            edge_index    = torch.tensor([[0], [1]], dtype=torch.long)
            edge_attr_np  = self.edge_scaler.transform(np.array([[amt, dwell]]))
            edge_attr     = torch.tensor(edge_attr_np, dtype=torch.float32)

            with torch.no_grad():
                logit = self.gnn(x, edge_index, edge_attr)
                prob  = torch.sigmoid(logit).item()

            # Use optimal threshold saved from training to decide high/low risk
            # but still return a continuous 0â€“100 score
            raw_score = prob * 100.0

            # Boost score if above optimal threshold (cross-boundary penalty)
            if prob >= self.optimal_threshold:
                raw_score = min(100.0, raw_score * 1.15)

            return float(raw_score)

        except Exception:
            return -1


# Global singleton
ml_models = MLModelService()

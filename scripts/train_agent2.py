"""
VaultMind 2.0 - train_agent2.py
===================================================================
Agent 2: FundFlow GNN - Edge Classification for Fraud Detection
UPGRADED:
  - Node features: degree + fraud-rate per node (not just ones)
  - Dropout layers added to prevent overfitting
  - Early stopping (patience=10) to avoid over-training
  - Epochs 40 → 100
  - Optimal threshold via F1 search (not hardcoded 0.5)
  - Graph edge weight by transaction frequency

Features:  Node embeddings (GraphSAGE), Edge features (amount, dwell_time_seconds)
Model:     2-layer GraphSAGE + Dropout + Edge Classifier
Artifacts: models/agent2_gnn.pth, models/account_mapping.pkl
===================================================================
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from torch_geometric.data import Data
from torch_geometric.nn import SAGEConv

# -- Configuration ---------------------------------------------------------
SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
PRODUCTION_CSV = os.path.join(SCRIPT_DIR, "..", "server", "data", "Testing_data", "live_demo_stream.csv")
MODEL_DIR = os.path.join(SCRIPT_DIR, "..", "server", "models")

# Training hyperparameters
HIDDEN_CHANNELS = 64        # was 32 — more capacity
EPOCHS          = 100       # was 40
LR              = 0.005
DROPOUT         = 0.3       # NEW — prevents overfitting
PATIENCE        = 10        # NEW — early stopping patience
DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

np.random.seed(42)
torch.manual_seed(42)


# ==========================================================================
# MODEL DEFINITION
# ==========================================================================

class GraphSAGEEdgeClassifier(nn.Module):
    def __init__(self, in_channels, hidden_channels, edge_in_channels, dropout=0.3):
        super(GraphSAGEEdgeClassifier, self).__init__()

        self.dropout = dropout

        # GraphSAGE layers
        self.conv1 = SAGEConv(in_channels, hidden_channels)
        self.conv2 = SAGEConv(hidden_channels, hidden_channels)

        # Edge classifier MLP — now with BatchNorm + Dropout
        mlp_in = hidden_channels * 2 + edge_in_channels
        self.edge_mlp = nn.Sequential(
            nn.Linear(mlp_in, hidden_channels),
            nn.BatchNorm1d(hidden_channels),        # NEW — stabilises training
            nn.ReLU(),
            nn.Dropout(p=dropout),                  # NEW — prevents overfitting
            nn.Linear(hidden_channels, hidden_channels // 2),
            nn.ReLU(),
            nn.Linear(hidden_channels // 2, 1)
        )

    def forward(self, x, edge_index, edge_attr):
        # Node embedding pass
        h = self.conv1(x, edge_index)
        h = F.relu(h)
        h = F.dropout(h, p=self.dropout, training=self.training)  # NEW
        h = self.conv2(h, edge_index)
        h = F.relu(h)

        # Concat source + destination embeddings + edge features
        src, dst = edge_index
        edge_repr = torch.cat([h[src], h[dst], edge_attr], dim=1)
        return self.edge_mlp(edge_repr).squeeze(-1)


# ==========================================================================
# HELPER: Find optimal classification threshold
# ==========================================================================

def find_optimal_threshold(y_true, y_probs):
    """
    Instead of hardcoding 0.5, sweep thresholds and pick the one
    that maximises F1-score on the validation set.
    """
    best_threshold, best_f1 = 0.5, 0.0
    for t in np.arange(0.1, 0.9, 0.01):
        preds = (y_probs >= t).astype(int)
        f1 = f1_score(y_true, preds, zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = t
    return best_threshold, best_f1


# ==========================================================================
# HELPER: Build meaningful node features
# ==========================================================================

def build_node_features(df, account_mapping, num_nodes):
    """
    Instead of torch.ones, give each node real features:
      - out_degree   : how many transactions sent
      - in_degree    : how many transactions received
      - fraud_rate   : fraction of edges involving this node that are fraud
    """
    feat = np.zeros((num_nodes, 3), dtype=np.float32)

    for _, row in df.iterrows():
        src_id = account_mapping.get(str(row.get("account_touched", "")), None)
        dst_id = account_mapping.get(str(row.get("destination_account", "")), None)
        fraud = row.get("is_fraud_flag", 0)

        if src_id is not None:
            feat[src_id, 0] += 1          # out_degree
            feat[src_id, 2] += fraud      # fraud involvement count

        if dst_id is not None:
            feat[dst_id, 1] += 1          # in_degree
            feat[dst_id, 2] += fraud

    # Normalise fraud count → fraud rate
    total_degree = feat[:, 0] + feat[:, 1]
    total_degree = np.where(total_degree == 0, 1, total_degree)
    feat[:, 2] = feat[:, 2] / total_degree

    # StandardScale all node features
    scaler = StandardScaler()
    feat = scaler.fit_transform(feat)
    return torch.tensor(feat, dtype=torch.float)


# ==========================================================================
# MAIN PIPELINE
# ==========================================================================

def main():
    print("=" * 65)
    print("  VaultMind 2.0 -- Agent 2: FundFlow GNN Training")
    print("  UPGRADED: Dropout + Node Features + Early Stopping")
    print("=" * 65)

    if not os.path.exists(PRODUCTION_CSV):
        print("\n[X] ERROR: Cannot find production data at:")
        print(f"    {PRODUCTION_CSV}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # 1. Load
    # ------------------------------------------------------------------
    print(f"\n[1/6] Loading PRODUCTION data: {PRODUCTION_CSV}")
    df = pd.read_csv(PRODUCTION_CSV)
    df["amount"] = df["amount"].fillna(0.0)
    df['dwell_time_seconds'] = df['dwell_time_seconds'].fillna(0.0)
    print(f"  [OK] {len(df):,} transactions loaded")

    # ------------------------------------------------------------------
    # 2. Build graph
    # ------------------------------------------------------------------
    print(f"\n[2/6] Constructing Graph...")

    all_entities = (
        set(df['account_touched'].dropna().astype(str).unique())
        .union(set(df['destination_account'].dropna().astype(str).unique()))
        .union(set(df['emp_id'].dropna().astype(str).unique()))
        .union(set(df['ip_address'].dropna().astype(str).unique()))
    )
    all_accounts    = sorted(list(all_entities))
    num_nodes       = len(all_accounts)
    account_mapping = {acc: i for i, acc in enumerate(all_accounts)}

    src_nodes = df['account_touched'].astype(str).map(account_mapping).values
    dst_nodes = df['destination_account'].astype(str).map(account_mapping).values

    valid_mask = ~pd.isnull(src_nodes) & ~pd.isnull(dst_nodes)
    if not valid_mask.all():
        print(f"  [!] Dropping {(~valid_mask).sum()} rows with unmapped nodes")
        df        = df[valid_mask].reset_index(drop=True)
        src_nodes = src_nodes[valid_mask]
        dst_nodes = dst_nodes[valid_mask]

    edge_index = torch.tensor(
        np.vstack([src_nodes.astype(int), dst_nodes.astype(int)]),
        dtype=torch.long
    )

    # Edge features
    edge_scaler       = StandardScaler()
    edge_features_np  = edge_scaler.fit_transform(df[['amount', 'dwell_time_seconds']])
    edge_attr         = torch.tensor(edge_features_np, dtype=torch.float)

    # Node features — meaningful instead of ones
    x = build_node_features(df, account_mapping, num_nodes)   # shape (N, 3)

    y = torch.tensor(df['is_fraud_flag'].values, dtype=torch.float)

    print(f"  [OK] Nodes : {num_nodes:,}")
    print(f"  [OK] Edges : {edge_index.shape[1]:,}")
    print(f"  [OK] Fraud : {int(y.sum())} ({y.mean()*100:.2f}%)")
    print(f"  [OK] Node feature dim: {x.shape[1]} (degree + fraud_rate)")

    # ------------------------------------------------------------------
    # 3. Train / val split
    # ------------------------------------------------------------------
    indices   = np.arange(edge_index.shape[1])
    train_idx, val_idx = train_test_split(
        indices, test_size=0.2, stratify=y.numpy(), random_state=42
    )
    train_mask = torch.zeros(edge_index.shape[1], dtype=torch.bool)
    val_mask   = torch.zeros(edge_index.shape[1], dtype=torch.bool)
    train_mask[train_idx] = True
    val_mask[val_idx]     = True

    # ------------------------------------------------------------------
    # 4. Model + loss
    # ------------------------------------------------------------------
    print(f"\n[3/6] Initializing upgraded GraphSAGE Model...")
    model = GraphSAGEEdgeClassifier(
        in_channels      = x.shape[1],   # 3 now instead of 1
        hidden_channels  = HIDDEN_CHANNELS,
        edge_in_channels = 2,
        dropout          = DROPOUT,
    ).to(DEVICE)

    num_pos    = y[train_mask].sum()
    num_neg    = (~y[train_mask].bool()).sum()
    pos_weight = (num_neg / num_pos) if num_pos > 0 else torch.tensor(1.0)
    criterion  = nn.BCEWithLogitsLoss(pos_weight=pos_weight.to(DEVICE))
    optimizer  = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=1e-4)

    # Move to device
    x          = x.to(DEVICE)
    edge_index = edge_index.to(DEVICE)
    edge_attr  = edge_attr.to(DEVICE)
    y          = y.to(DEVICE)
    train_mask = train_mask.to(DEVICE)
    val_mask   = val_mask.to(DEVICE)

    # ------------------------------------------------------------------
    # 5. Training loop with early stopping
    # ------------------------------------------------------------------
    print(f"\n[4/6] Training {EPOCHS} epochs on {DEVICE} "
          f"(early stop patience={PATIENCE})...")

    best_val_auc    = 0.0
    best_state      = None
    patience_counter = 0

    for epoch in range(1, EPOCHS + 1):
        model.train()
        optimizer.zero_grad()
        out  = model(x, edge_index, edge_attr)
        loss = criterion(out[train_mask], y[train_mask])
        loss.backward()
        optimizer.step()

        if epoch % 5 == 0 or epoch == 1:
            model.eval()
            with torch.no_grad():
                val_out    = model(x, edge_index, edge_attr)[val_mask]
                val_loss   = criterion(val_out, y[val_mask])
                val_probs  = torch.sigmoid(val_out).cpu().numpy()
                val_labels = y[val_mask].cpu().numpy()
                val_preds  = (val_probs > 0.5).astype(int)

                roc_auc = (roc_auc_score(val_labels, val_probs)
                           if len(np.unique(val_labels)) > 1 else 0)
                f1      = f1_score(val_labels, val_preds, zero_division=0)

            print(f"  Epoch {epoch:03d} | "
                  f"Train Loss: {loss.item():.4f} | "
                  f"Val Loss: {val_loss.item():.4f} | "
                  f"Val AUC: {roc_auc:.4f} | "
                  f"Val F1: {f1:.4f}")

            # Early stopping check
            if roc_auc > best_val_auc:
                best_val_auc = roc_auc
                best_state   = {k: v.clone() for k, v in model.state_dict().items()}
                patience_counter = 0
            else:
                patience_counter += 1
                if patience_counter >= PATIENCE:
                    print(f"\n  [!] Early stopping at epoch {epoch} "
                          f"(no improvement for {PATIENCE} checks)")
                    break

    # Restore best weights
    if best_state:
        model.load_state_dict(best_state)
        print(f"  [OK] Restored best model (Val AUC={best_val_auc:.4f})")

    # ------------------------------------------------------------------
    # 6. Final evaluation with optimal threshold
    # ------------------------------------------------------------------
    print(f"\n[5/6] Final evaluation with optimal threshold search...")
    model.eval()
    with torch.no_grad():
        val_out    = model(x, edge_index, edge_attr)[val_mask]
        val_probs  = torch.sigmoid(val_out).cpu().numpy()
        val_labels = y[val_mask].cpu().numpy()

    optimal_threshold, _ = find_optimal_threshold(val_labels, val_probs)
    val_preds = (val_probs >= optimal_threshold).astype(int)

    final_auc  = roc_auc_score(val_labels, val_probs)
    final_f1   = f1_score(val_labels, val_preds, zero_division=0)
    final_prec = precision_score(val_labels, val_preds, zero_division=0)
    final_rec  = recall_score(val_labels, val_preds, zero_division=0)

    print(f"\n  +---------------------------------------------------+")
    print(f"  |  Final Validation Metrics                         |")
    print(f"  +---------------------------------------------------+")
    print(f"  |  Optimal Threshold         : {optimal_threshold:.2f}                |")
    print(f"  |  Validation AUC-ROC        : {final_auc:.4f}              |")
    print(f"  |  Validation F1-Score       : {final_f1:.4f}              |")
    print(f"  |  Validation Precision      : {final_prec:.4f}              |")
    print(f"  |  Validation Recall         : {final_rec:.4f}              |")
    print(f"  +---------------------------------------------------+")

    # ------------------------------------------------------------------
    # 7. Save
    # ------------------------------------------------------------------
    print(f"\n[6/6] Saving model artifacts...")
    os.makedirs(MODEL_DIR, exist_ok=True)

    model_path   = os.path.join(MODEL_DIR, "agent2_gnn.pth")
    mapping_path = os.path.join(MODEL_DIR, "account_mapping.pkl")

    torch.save(model.state_dict(), model_path)
    joblib.dump({
        "account_mapping":     account_mapping,
        "edge_scaler":         edge_scaler,
        "optimal_threshold":   optimal_threshold,   # saved for inference
    }, mapping_path)

    model_size = os.path.getsize(model_path) / 1024
    print(f"  [OK] Model   -> {model_path} ({model_size:.1f} KB)")
    print(f"  [OK] Mapping -> {mapping_path}")
    print(f"\n{'=' * 65}")
    print(f"  [DONE] Agent 2 (FundFlow GNN) training complete!")
    print(f"{'=' * 65}")


if __name__ == "__main__":
    main()

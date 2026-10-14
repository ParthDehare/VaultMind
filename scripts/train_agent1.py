"""
VaultMind 3.0 - train_agent1.py
===================================================================
Agent 1: BehaviourWatch - Behavioural & Velocity Anomaly Detection
UPGRADED: XGBoost + Stratified K-Fold CV + Dynamic Extreme Imbalance Calibration

Features:  amount, dwell_time_seconds, records_accessed, login_hour
           + amount_vs_user_avg, time_since_last_txn, txn_count_1hr
Model:     XGBClassifier with dynamically calibrated scale_pos_weight & PR-AUC metric
Artifacts: models/agent1_iso_forest.pkl, models/agent1_scaler.pkl, models/cv_evaluation_report.json
===================================================================
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc, precision_score, recall_score, f1_score
from imblearn.over_sampling import SMOTE

# -- Configuration ---------------------------------------------------------
SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
PRODUCTION_CSV = os.path.join(SCRIPT_DIR, "..", "server", "data", "Testing_data", "live_demo_stream.csv")
MODEL_DIR      = os.path.join(SCRIPT_DIR, "..", "server", "models")

BASE_FEATURES = ["amount", "dwell_time_seconds", "records_accessed", "login_hour"]
ALL_FEATURES  = BASE_FEATURES + [
    "amount_vs_user_avg",
    "time_since_last_txn",
    "txn_count_1hr",
]

np.random.seed(42)

# --------------------------------------------------------------------------
def engineer_velocity_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add 3 velocity/context features that capture PATTERNS over time,
    not just single-transaction values.
    """
    df = df.copy()

    # --- Feature 1: amount vs this user's rolling 30-txn average ----------
    if "user_id" in df.columns and "amount" in df.columns:
        user_avg = (df.groupby("user_id")["amount"]
                      .transform(lambda x: x.rolling(30, min_periods=1).mean()))
        df["amount_vs_user_avg"] = df["amount"] / user_avg.replace(0, 1)
    else:
        df["amount_vs_user_avg"] = 1.0

    # --- Feature 2: seconds since the same user's previous transaction ----
    if "user_id" in df.columns and "timestamp" in df.columns:
        df = df.sort_values(["user_id", "timestamp"])
        df["time_since_last_txn"] = (
            df.groupby("user_id")["timestamp"]
              .diff()
              .dt.total_seconds()
              .fillna(0)
        )
    else:
        df["time_since_last_txn"] = 0.0

    # --- Feature 3: transaction count for this user in the last hour ------
    if "user_id" in df.columns and "timestamp" in df.columns:
        df["txn_count_1hr"] = (
            df.groupby("user_id")["timestamp"]
              .transform(lambda x: x.expanding().count())
        )
    else:
        df["txn_count_1hr"] = 1.0

    return df


# --------------------------------------------------------------------------
def main():
    print("=" * 70)
    print("  VaultMind 3.0 -- Agent 1: BehaviourWatch Training Pipeline")
    print("  UPGRADED: Dynamic Extreme Imbalance Calibration + Stratified 5-Fold CV")
    print("=" * 70)

    # 1. Load data
    if not os.path.exists(PRODUCTION_CSV):
        print(f"\n[X] ERROR: Cannot find production data at: {PRODUCTION_CSV}")
        sys.exit(1)

    print(f"\n[1/6] Loading PRODUCTION data: {PRODUCTION_CSV}")
    df = pd.read_csv(PRODUCTION_CSV)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    if "login_hour" not in df.columns and "timestamp" in df.columns:
        df["login_hour"] = pd.to_datetime(df["timestamp"]).dt.hour

    missing_base = [c for c in BASE_FEATURES if c not in df.columns]
    if missing_base:
        print(f"  [X] ERROR: Missing base columns {missing_base}")
        sys.exit(1)

    print(f"  [OK] Production data loaded -- {len(df):,} transactions")

    # 2. Velocity / context feature engineering
    print(f"\n[2/6] Engineering velocity & context features...")
    df = engineer_velocity_features(df)
    print(f"  [OK] New features added: amount_vs_user_avg, time_since_last_txn, txn_count_1hr")

    # 3. Train / test split (stratified)
    print(f"\n[3/6] Preparing data & Train/Test Split...")
    X = df[ALL_FEATURES].fillna(0.0).values
    y = df["is_fraud_flag"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    neg_count = (y_train == 0).sum()
    pos_count = max(1, (y_train == 1).sum())
    # Calibrated scale_pos_weight directly from true imbalance ratio
    dynamic_spw = float(neg_count / pos_count)

    print(f"  [OK] Split -> Train={len(X_train):,} Test={len(X_test):,}")
    print(f"  [OK] Fraud in train={y_train.sum():,} ({y_train.mean()*100:.2f}%)")
    print(f"  [OK] Calibrated scale_pos_weight: {dynamic_spw:.2f}")

    xgb_params = {
        "n_estimators":     300,
        "max_depth":        6,
        "learning_rate":    0.08,
        "scale_pos_weight": dynamic_spw,
        "subsample":        0.8,
        "colsample_bytree": 0.8,
        "use_label_encoder": False,
        "eval_metric":      "aucpr",
        "random_state":     42,
    }

    # 4. Stratified K-Fold Cross Validation across 5 Folds
    print(f"\n[4/6] Running Stratified 5-Fold Cross Validation...")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    cv_roc_aucs = []
    cv_pr_aucs = []
    cv_precisions = []
    cv_recalls = []
    cv_f1s = []

    for fold, (train_idx, val_idx) in enumerate(skf.split(X_train, y_train), 1):
        X_fold_tr, y_fold_tr = X_train[train_idx], y_train[train_idx]
        X_fold_val, y_fold_val = X_train[val_idx], y_train[val_idx]

        fold_scaler = StandardScaler()
        X_fold_tr_scaled = fold_scaler.fit_transform(X_fold_tr)
        X_fold_val_scaled = fold_scaler.transform(X_fold_val)

        # Optional moderate SMOTE to stabilize minority gradients without distorting precision
        sm = SMOTE(sampling_strategy=0.3, random_state=42 + fold)
        X_fold_tr_bal, y_fold_tr_bal = sm.fit_resample(X_fold_tr_scaled, y_fold_tr)

        fold_model = XGBClassifier(**xgb_params)
        fold_model.fit(X_fold_tr_bal, y_fold_tr_bal, verbose=False)

        y_fold_probs = fold_model.predict_proba(X_fold_val_scaled)[:, 1]
        y_fold_preds = (y_fold_probs >= 0.5).astype(int)

        roc_auc = roc_auc_score(y_fold_val, y_fold_probs)
        precision, recall, _ = precision_recall_curve(y_fold_val, y_fold_probs)
        pr_auc = auc(recall, precision)
        prec_score = precision_score(y_fold_val, y_fold_preds, zero_division=0)
        rec_score = recall_score(y_fold_val, y_fold_preds, zero_division=0)
        f1 = f1_score(y_fold_val, y_fold_preds, zero_division=0)

        cv_roc_aucs.append(roc_auc)
        cv_pr_aucs.append(pr_auc)
        cv_precisions.append(prec_score)
        cv_recalls.append(rec_score)
        cv_f1s.append(f1)
        print(f"       Fold {fold}: ROC-AUC={roc_auc:.4f} | PR-AUC={pr_auc:.4f} | F1={f1:.4f} | Recall={rec_score*100:.1f}%")

    print(f"  [OK] 5-Fold CV Summary: ROC-AUC={np.mean(cv_roc_aucs):.4f} (Â±{np.std(cv_roc_aucs):.4f}) | PR-AUC={np.mean(cv_pr_aucs):.4f}")

    # 5. Train final production model on full training set
    print(f"\n[5/6] Training Final Production XGBoost Classifier...")
    final_scaler = StandardScaler()
    X_train_scaled = final_scaler.fit_transform(X_train)
    X_test_scaled = final_scaler.transform(X_test)

    sm_final = SMOTE(sampling_strategy=0.3, random_state=42)
    X_train_bal, y_train_bal = sm_final.fit_resample(X_train_scaled, y_train)

    model = XGBClassifier(**xgb_params)
    model.fit(X_train_bal, y_train_bal, eval_set=[(X_test_scaled, y_test)], verbose=False)
    print(f"  [OK] Production XGBoost classifier trained successfully")

    # 6. Evaluate on Test Set & Save CV Report
    print(f"\n[6/6] Final Hold-Out Test Set Evaluation...")
    y_pred_binary = model.predict(X_test_scaled)
    y_scores      = model.predict_proba(X_test_scaled)[:, 1]

    true_fraud      = y_test.sum()
    detected_fraud  = ((y_pred_binary == 1) & (y_test == 1)).sum()
    false_positives = ((y_pred_binary == 1) & (y_test == 0)).sum()

    test_recall    = detected_fraud / true_fraud * 100 if true_fraud > 0 else 0
    test_precision = (detected_fraud / (detected_fraud + false_positives) * 100
                      if (detected_fraud + false_positives) > 0 else 0)
    test_roc_auc   = roc_auc_score(y_test, y_scores)
    prec_curve, rec_curve, _ = precision_recall_curve(y_test, y_scores)
    test_pr_auc    = auc(rec_curve, prec_curve)

    print(f"  +---------------------------------------------------+")
    print(f"  |  Production Test Set Results                      |")
    print(f"  +---------------------------------------------------+")
    print(f"  |  True fraud in test set    : {true_fraud:>6,}              |")
    print(f"  |  Fraud caught by model     : {detected_fraud:>6,}              |")
    print(f"  |  False positives           : {false_positives:>6,}              |")
    print(f"  |  Recall (fraud detection)  : {test_recall:>6.1f}%             |")
    print(f"  |  Precision                 : {test_precision:>6.1f}%             |")
    print(f"  |  ROC AUC Score             : {test_roc_auc:>6.4f}              |")
    print(f"  |  PR AUC Score              : {test_pr_auc:>6.4f}              |")
    print(f"  +---------------------------------------------------+")

    os.makedirs(MODEL_DIR, exist_ok=True)
    model_path  = os.path.join(MODEL_DIR, "agent1_iso_forest.pkl")
    scaler_path = os.path.join(MODEL_DIR, "agent1_scaler.pkl")
    cv_report_path = os.path.join(MODEL_DIR, "cv_evaluation_report.json")

    joblib.dump(model, model_path)
    joblib.dump(final_scaler, scaler_path)

    report_data = {
        "model": "XGBClassifier (Agent 1 - BehaviourWatch)",
        "calibrated_scale_pos_weight": dynamic_spw,
        "cross_validation_5fold": {
            "mean_roc_auc": float(np.mean(cv_roc_aucs)),
            "std_roc_auc": float(np.std(cv_roc_aucs)),
            "mean_pr_auc": float(np.mean(cv_pr_aucs)),
            "mean_f1": float(np.mean(cv_f1s)),
            "mean_precision": float(np.mean(cv_precisions)),
            "mean_recall": float(np.mean(cv_recalls))
        },
        "test_set_evaluation": {
            "true_fraud": int(true_fraud),
            "detected_fraud": int(detected_fraud),
            "false_positives": int(false_positives),
            "recall_percent": float(test_recall),
            "precision_percent": float(test_precision),
            "roc_auc": float(test_roc_auc),
            "pr_auc": float(test_pr_auc)
        }
    }

    with open(cv_report_path, "w") as rf:
        json.dump(report_data, rf, indent=4)

    print(f"\n  [OK] Model saved  -> {model_path}")
    print(f"  [OK] Scaler saved -> {scaler_path}")
    print(f"  [OK] CV Report    -> {cv_report_path}")
    print(f"\n{'=' * 70}")
    print(f"  [DONE] Agent 1 (BehaviourWatch) training & calibration complete!")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()

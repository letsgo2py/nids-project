import pandas as pd
import numpy as np
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_score, recall_score, f1_score
)
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from parser import load_and_parse, FEATURES

# ── Config ───────────────────────────────────────────────
NORMAL_FILE = "data/monday.csv"
ATTACK_FILE = "data/friday.csv"
# ─────────────────────────────────────────────────────────

def load_labels(filepath):
    """Load the raw Label column from friday.csv before parser strips it."""
    print("[Evaluate] Reading ground truth labels from friday.csv ...")
    df_raw = pd.read_csv(filepath, low_memory=False)
    df_raw.columns = df_raw.columns.str.strip()

    # Keep features + Label together
    available = [c for c in FEATURES if c in df_raw.columns]
    if 'Label' not in df_raw.columns:
        raise ValueError("No 'Label' column found in friday.csv")

    df = df_raw[available + ['Label']].copy()
    df.replace([float('inf'), float('-inf')], pd.NA, inplace=True)
    df.dropna(inplace=True)
    df['Label'] = df['Label'].str.strip()
    return df


def evaluate_rules(df):
    """
    Run signature rules and evaluate against ground truth labels.
    Any non-BENIGN label = true attack.
    """
    print("\n" + "="*50)
    print("  RULE-BASED DETECTION — EVALUATION")
    print("="*50)

    # Ground truth: 1 = attack, 0 = benign
    y_true = (df['Label'] != 'BENIGN').astype(int)

    # Apply each rule and flag as predicted attack
    flagged = pd.Series(False, index=df.index)

    # Rule 1 — SYN Flood
    flagged |= (df['SYN Flag Count'] > 5) & (df['ACK Flag Count'] == 0)

    # Rule 2 — Port Scan
    flagged |= (
        (df['Dst Port'] < 1024) &
        (df['Flow Duration'] < 1000) &
        (df['Total Fwd Packet'] <= 2)
    )

    # Rule 3 — Large Transfer
    threshold_99 = df['Total Length of Fwd Packet'].quantile(0.99)
    flagged |= df['Total Length of Fwd Packet'] > threshold_99

    # Rule 4 — High Packet Rate
    threshold_995 = df['Flow Packets/s'].quantile(0.995)
    flagged |= df['Flow Packets/s'] > threshold_995

    y_pred = flagged.astype(int)

    # Metrics
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall    = recall_score(y_true, y_pred, zero_division=0)
    f1        = f1_score(y_true, y_pred, zero_division=0)

    total       = len(y_true)
    true_atk    = y_true.sum()
    detected    = y_pred.sum()
    tp          = ((y_pred == 1) & (y_true == 1)).sum()
    fp          = ((y_pred == 1) & (y_true == 0)).sum()
    fn          = ((y_pred == 0) & (y_true == 1)).sum()
    tn          = ((y_pred == 0) & (y_true == 0)).sum()

    print(f"\n  Total flows analysed : {total:>10,}")
    print(f"  True attacks in data : {true_atk:>10,}")
    print(f"  Flows flagged        : {detected:>10,}")
    print(f"\n  True Positives  (TP) : {tp:>10,}  (attacks correctly caught)")
    print(f"  False Positives (FP) : {fp:>10,}  (benign wrongly flagged)")
    print(f"  False Negatives (FN) : {fn:>10,}  (attacks missed)")
    print(f"  True Negatives  (TN) : {tn:>10,}  (benign correctly ignored)")
    print(f"\n  Precision            : {precision:>10.4f}  (of all alerts, how many real?)")
    print(f"  Recall               : {recall:>10.4f}  (of all attacks, how many caught?)")
    print(f"  F1 Score             : {f1:>10.4f}  (balance of precision & recall)")

    # Per-attack-type breakdown
    print("\n  --- Attack type breakdown ---")
    attack_types = df[y_pred == 1]['Label'].value_counts()
    for label, count in attack_types.items():
        print(f"    {label:<40} {count:>8,}")

    return {"precision": precision, "recall": recall, "f1": f1,
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}


def evaluate_ml(df):
    """
    Train Isolation Forest on monday (benign), predict on friday.
    Evaluate against ground truth labels.
    """
    print("\n" + "="*50)
    print("  ML ANOMALY DETECTION — EVALUATION")
    print("="*50)

    # Load clean normal traffic for training
    df_normal = load_and_parse(NORMAL_FILE, label_override='BENIGN')

    numeric_cols = [c for c in FEATURES if c in df.columns]

    # Scale
    scaler = StandardScaler()
    X_train = scaler.fit_transform(df_normal[numeric_cols].fillna(0))
    X_test  = scaler.transform(df[numeric_cols].fillna(0))

    # Train
    print(f"\n[Evaluate] Training Isolation Forest on {len(df_normal):,} benign flows ...")
    model = IsolationForest(
        n_estimators=100,
        contamination=0.02,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train)

    # Predict: -1 = anomaly → 1 (attack), 1 = normal → 0 (benign)
    raw_preds = model.predict(X_test)
    y_pred = (raw_preds == -1).astype(int)
    y_true = (df['Label'] != 'BENIGN').astype(int)

    # Metrics
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall    = recall_score(y_true, y_pred, zero_division=0)
    f1        = f1_score(y_true, y_pred, zero_division=0)

    total    = len(y_true)
    true_atk = y_true.sum()
    detected = y_pred.sum()
    tp       = ((y_pred == 1) & (y_true == 1)).sum()
    fp       = ((y_pred == 1) & (y_true == 0)).sum()
    fn       = ((y_pred == 0) & (y_true == 1)).sum()
    tn       = ((y_pred == 0) & (y_true == 0)).sum()

    print(f"\n  Total flows analysed : {total:>10,}")
    print(f"  True attacks in data : {true_atk:>10,}")
    print(f"  Anomalies detected   : {detected:>10,}")
    print(f"\n  True Positives  (TP) : {tp:>10,}  (attacks correctly caught)")
    print(f"  False Positives (FP) : {fp:>10,}  (benign wrongly flagged)")
    print(f"  False Negatives (FN) : {fn:>10,}  (attacks missed)")
    print(f"  True Negatives  (TN) : {tn:>10,}  (benign correctly ignored)")
    print(f"\n  Precision            : {precision:>10.4f}  (of all alerts, how many real?)")
    print(f"  Recall               : {recall:>10.4f}  (of all attacks, how many caught?)")
    print(f"  F1 Score             : {f1:>10.4f}  (balance of precision & recall)")

    # Which attack types did ML catch?
    print("\n  --- Attack types caught by ML ---")
    attack_types = df[y_pred == 1]['Label'].value_counts()
    for label, count in attack_types.items():
        print(f"    {label:<40} {count:>8,}")

    return {"precision": precision, "recall": recall, "f1": f1,
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}


def print_final_summary(rule_metrics, ml_metrics):
    print("\n" + "="*50)
    print("  FINAL COMPARISON SUMMARY")
    print("="*50)
    print(f"\n  {'Metric':<15} {'Rules':>12} {'ML (IsoForest)':>16}")
    print(f"  {'-'*43}")
    print(f"  {'Precision':<15} {rule_metrics['precision']:>12.4f} {ml_metrics['precision']:>16.4f}")
    print(f"  {'Recall':<15} {rule_metrics['recall']:>12.4f} {ml_metrics['recall']:>16.4f}")
    print(f"  {'F1 Score':<15} {rule_metrics['f1']:>12.4f} {ml_metrics['f1']:>16.4f}")
    print(f"  {'TP':<15} {rule_metrics['tp']:>12,} {ml_metrics['tp']:>16,}")
    print(f"  {'FP':<15} {rule_metrics['fp']:>12,} {ml_metrics['fp']:>16,}")
    print(f"  {'FN':<15} {rule_metrics['fn']:>12,} {ml_metrics['fn']:>16,}")
    print()
    print("  Precision = of all flows we flagged, how many were real attacks?")
    print("  Recall    = of all real attacks, how many did we catch?")
    print("  F1        = harmonic mean of precision and recall (0-1, higher = better)")
    print("="*50 + "\n")


if __name__ == "__main__":
    df = load_labels(ATTACK_FILE)
    print(f"[Evaluate] Label distribution in friday.csv:")
    print(df['Label'].value_counts().to_string())

    rule_metrics = evaluate_rules(df)
    ml_metrics   = evaluate_ml(df)
    print_final_summary(rule_metrics, ml_metrics)
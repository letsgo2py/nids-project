from parser import load_and_parse
from rules import run_rules
from anomaly import run_anomaly_detection
from alerts import save_alerts

# ── Config ──────────────────────────────────────────────
NORMAL_FILE = "data/monday.csv"   # benign traffic → train the ML model
ATTACK_FILE = "data/friday.csv"   # mixed traffic  → run detection on this
# ────────────────────────────────────────────────────────

def main():
    print("\n===== NIDS Pipeline Starting =====\n")

    # Stage 1: Parse
    df_normal = load_and_parse(NORMAL_FILE, label_override='BENIGN')
    df_attack = load_and_parse(ATTACK_FILE)

    # Stage 2: Signature-based rule detection on attack file
    print("\n--- Stage 2: Signature Rules ---")
    rule_alerts = run_rules(df_attack)

    # Stage 3: ML anomaly detection
    # Train on normal traffic, detect anomalies in attack file
    print("\n--- Stage 3: ML Anomaly Detection ---")
    anomaly_results = run_anomaly_detection(
        df_train=df_normal,
        df_test=df_attack,
        contamination=0.02   # expect ~2% anomalies
    )

    # Stage 4: Save alerts and generate report
    print("\n--- Stage 4: Saving Alerts ---")
    save_alerts(rule_alerts, anomaly_results)

    print("===== NIDS Pipeline Complete =====\n")

if __name__ == "__main__":
    main()

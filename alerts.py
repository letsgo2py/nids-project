import pandas as pd
import json
import os
from datetime import datetime

ALERTS_DIR = "alerts"

def save_alerts(rule_alerts, anomaly_df):
    """
    Save rule-based and ML-based alerts to files.
    Generates a JSON summary report.
    """
    os.makedirs(ALERTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # --- Rule-based alerts CSV ---
    rule_path = os.path.join(ALERTS_DIR, f"rule_alerts_{timestamp}.csv")
    if rule_alerts is not None and len(rule_alerts) > 0:
        rule_alerts.to_csv(rule_path, index=False)
        print(f"[Alerts] Rule-based alerts saved → {rule_path}")
    else:
        print("[Alerts] No rule-based alerts to save.")

    # --- ML anomaly alerts CSV ---
    ml_path = os.path.join(ALERTS_DIR, f"ml_anomalies_{timestamp}.csv")
    if anomaly_df is not None and 'Anomaly' in anomaly_df.columns:
        anomalies = anomaly_df[anomaly_df['Anomaly'] == -1].sort_values('Anomaly_Score')
        anomalies.to_csv(ml_path, index=False)
        print(f"[Alerts] ML anomaly alerts saved → {ml_path}")
    else:
        anomalies = pd.DataFrame()
        print("[Alerts] No ML anomaly data to save.")

    # --- JSON summary report ---
    report = {
        "generated_at": timestamp,
        "rule_based_alerts": {
            "total": int(len(rule_alerts)) if rule_alerts is not None and len(rule_alerts) > 0 else 0,
            "breakdown": (
                rule_alerts['Rule'].value_counts().to_dict()
                if rule_alerts is not None and 'Rule' in rule_alerts.columns
                else {}
            )
        },
        "ml_anomaly_detection": {
            "total_flows_analysed": int(len(anomaly_df)) if anomaly_df is not None else 0,
            "anomalies_detected": int(len(anomalies)) if len(anomalies) > 0 else 0,
            "anomaly_rate_percent": round(
                100 * len(anomalies) / len(anomaly_df), 2
            ) if anomaly_df is not None and len(anomaly_df) > 0 else 0
        }
    }

    report_path = os.path.join(ALERTS_DIR, f"summary_{timestamp}.json")
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"[Alerts] Summary report saved → {report_path}")
    print("\n========== SUMMARY ==========")
    print(json.dumps(report, indent=2))
    print("==============================\n")

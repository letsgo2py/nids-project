import pandas as pd

def run_rules(df):
    """
    Signature-based detection rules.
    Returns a DataFrame of flagged flows with reason.
    """
    alerts = []

    # Rule 1 — SYN Flood: high SYN count, low ACK count (DDoS pattern)
    syn_flood = df[
        (df['SYN Flag Count'] > 5) &
        (df['ACK Flag Count'] == 0)
    ].copy()
    syn_flood['Rule'] = 'SYN Flood Detected'
    alerts.append(syn_flood)

    # Rule 2 — Port Scan: destination port < 1024 with very short flow duration
    port_scan = df[
        (df['Dst Port'] < 1024) &
        (df['Flow Duration'] < 1000) &
        (df['Total Fwd Packet'] <= 2)
    ].copy()
    port_scan['Rule'] = 'Possible Port Scan'
    alerts.append(port_scan)

    # Rule 3 — Large outbound transfer: unusually large fwd packet length
    large_transfer = df[
        df['Total Length of Fwd Packet'] > df['Total Length of Fwd Packet'].quantile(0.99)
    ].copy()
    large_transfer['Rule'] = 'Large Outbound Transfer'
    alerts.append(large_transfer)

    # Rule 4 — High flow rate: abnormally high packets per second
    high_rate = df[
        df['Flow Packets/s'] > df['Flow Packets/s'].quantile(0.995)
    ].copy()
    high_rate['Rule'] = 'High Packet Rate (Possible Flood)'
    alerts.append(high_rate)

    if not any(len(a) > 0 for a in alerts):
        print("[Rules] No rule-based alerts triggered.")
        return pd.DataFrame()

    result = pd.concat(alerts, ignore_index=True).drop_duplicates()
    print(f"[Rules] {len(result):,} flows flagged by signature rules")
    return result

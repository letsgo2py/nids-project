import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def run_anomaly_detection(df_train, df_test, contamination=0.01):
    """
    Train Isolation Forest on normal traffic (df_train).
    Predict anomalies on df_test.
    Returns df_test with an 'Anomaly' column (-1 = anomaly, 1 = normal).
    """
    # Select only numeric columns for ML
    numeric_cols = df_train.select_dtypes(include='number').columns.tolist()
    if 'Label' in numeric_cols:
        numeric_cols.remove('Label')

    print(f"[Anomaly] Training Isolation Forest on {len(df_train):,} normal flows...")
    print(f"[Anomaly] Features used: {len(numeric_cols)}")

    # Scale features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(df_train[numeric_cols].fillna(0))
    X_test  = scaler.transform(df_test[numeric_cols].fillna(0))

    # Train model
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train)

    # Predict on test data
    predictions = model.predict(X_test)
    scores = model.decision_function(X_test)

    df_result = df_test.copy()
    df_result['Anomaly'] = predictions        # -1 = anomaly, 1 = normal
    df_result['Anomaly_Score'] = scores       # lower = more anomalous

    anomaly_count = (df_result['Anomaly'] == -1).sum()
    print(f"[Anomaly] {anomaly_count:,} anomalous flows detected out of {len(df_result):,} total")

    return df_result

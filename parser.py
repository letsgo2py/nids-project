import pandas as pd

FEATURES = [
    'Src Port', 'Dst Port', 'Protocol', 'Flow Duration',
    'Total Fwd Packet', 'Total Bwd packets',
    'Total Length of Fwd Packet', 'Total Length of Bwd Packet',
    'Flow Bytes/s', 'Flow Packets/s',
    'SYN Flag Count', 'ACK Flag Count', 'FIN Flag Count',
    'RST Flag Count', 'PSH Flag Count',
    'Packet Length Mean', 'Packet Length Std',
    'Average Packet Size', 'Down/Up Ratio',
    'Fwd Packets/s', 'Bwd Packets/s'
]

def load_and_parse(filepath, label_override=None):
    """
    Load a CSV file and return a cleaned DataFrame.
    label_override: 'BENIGN' or 'ATTACK' — use when file has no Label column.
    """
    print(f"[Parser] Loading {filepath} ...")
    df = pd.read_csv(filepath, low_memory=False)

    # Keep only columns that exist in this file
    available = [c for c in FEATURES if c in df.columns]
    df = df[available].copy()

    # Replace inf values and drop NaN rows
    df.replace([float('inf'), float('-inf')], pd.NA, inplace=True)
    df.dropna(inplace=True)

    if label_override:
        df['Label'] = label_override

    print(f"[Parser] Loaded {len(df):,} rows, {len(df.columns)} features")
    return df

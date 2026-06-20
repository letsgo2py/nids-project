# 🛡️ NIDS — Network Intrusion Detection System

A Python-based **Network Intrusion Detection System** that combines **signature-based rule detection** and **ML anomaly detection (Isolation Forest)** to identify malicious network traffic from real-world packet flow data.

> Built using the [CICIDS 2017 dataset](https://www.kaggle.com/datasets/bertvankeulen/cicids-2017?resource=download) from Kaggle — Monday (benign) and Friday (attack) traffic captures.

---

## 📌 Project Highlights

| Feature | Details |
|---|---|
| Dataset | CICIDS 2017 (Monday benign + Friday attack) |
| Detection Methods | Signature Rules + ML Anomaly Detection |
| ML Model | Isolation Forest (scikit-learn) |
| Attack Types Detected | SYN Flood, Port Scan, DDoS, Large Data Exfiltration |
| Output | CSV alert logs + JSON summary report |

---

## 🏗️ Architecture

```
friday.csv (attack traffic)  ──┐
                               ├──▶  parser.py  ──▶  rules.py   ──▶ Rule Alerts CSV
monday.csv (benign traffic)  ──┘         │
                                         └──────────▶  anomaly.py ──▶ ML Alerts CSV
                                                                  └──▶ summary.json
```

**Pipeline stages:**

1. **Parse** — Load & clean raw CSV flow data, drop NaN/inf values
2. **Signature Rules** — Flag known attack patterns (SYN Flood, Port Scan, etc.)
3. **ML Detection** — Train Isolation Forest on benign traffic; detect anomalies in attack traffic
4. **Alerts** — Save flagged flows to CSV files + generate a JSON summary report

---

## 📁 Project Structure

```
NIDS/
├── data/
│   ├── monday.csv          # Benign traffic (used to train ML model)
│   └── friday.csv          # Mixed attack traffic (detection target)
├── alerts/                 # Generated output (auto-created on run)
│   ├── rule_alerts_*.csv
│   ├── ml_anomalies_*.csv
│   └── summary_*.json
├── main.py                 # Pipeline entry point
├── parser.py               # Data loading & cleaning
├── rules.py                # Signature-based detection rules
├── anomaly.py              # Isolation Forest ML detection
├── alerts.py               # Alert saving & report generation
├── run_nids.sh             # Shell script runner
├── requirements.txt
└── README.md
```

---

## ⚙️ Setup & Installation

### 1. Clone the repository
```bash
git clone https://github.com/letsgo2py/nids-project.git
cd nids-project
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Add the dataset
Download the CICIDS 2017 dataset from [Kaggle](https://www.kaggle.com/datasets/bertvankeulen/cicids-2017) and place the files:
```
data/monday.csv    ← Monday WorkingHours.pcap_ISCX.csv
data/friday.csv    ← Friday WorkingHours.pcap_ISCX.csv
```

### 4. Run the pipeline
```bash
python main.py
# or
bash run_nids.sh
```

---

## 🔍 Detection Rules

| Rule | Condition | Attack Type |
|---|---|---|
| SYN Flood | SYN Flag Count > 5 AND ACK Flag Count = 0 | DDoS / SYN Flood |
| Port Scan | Dst Port < 1024, Flow Duration < 1000ms, Fwd Packets ≤ 2 | Reconnaissance |
| Large Transfer | Fwd Packet Length > 99th percentile | Data Exfiltration |
| High Packet Rate | Packets/s > 99.5th percentile | Flooding Attack |

---

## 🤖 ML Model — Isolation Forest

- **Trained on:** Monday benign traffic (normal baseline)
- **Tested on:** Friday mixed traffic
- **Algorithm:** Isolation Forest — unsupervised anomaly detection, ideal for cybersecurity where labeled attack data may not be available
- **Contamination:** 2% (expected anomaly rate in test data)
- **Output:** Anomaly score per flow; flows with score < threshold flagged as attacks

---

## 📊 Sample Output

```json
{
  "rule_based_alerts": {
    "total": 104945,
    "breakdown": {
      "Possible Port Scan": 97341,
      "Large Outbound Transfer": 5456,
      "High Packet Rate (Possible Flood)": 2072,
      "SYN Flood Detected": 76
    }
  },
  "ml_anomaly_detection": {
    "total_flows_analysed": 547557,
    "anomalies_detected": 58137,
    "anomaly_rate_percent": 10.62
  }
}
```

---

## 🧰 Tech Stack

- **Python 3.8+**
- **pandas** — data loading & manipulation
- **scikit-learn** — Isolation Forest, StandardScaler
- **NumPy** — numerical operations

---

## 🔗 Relevance to Cybersecurity Engineering

This project demonstrates hands-on experience with:
- **EDR/SIEM concepts** — flow-level detection logic mirrors real SIEM correlation rules
- **Anomaly detection** — unsupervised ML on network telemetry
- **Security automation** — end-to-end pipeline from raw data to structured alert output
- **Threat analysis** — implementation of detection logic for known attack patterns (DDoS, Port Scan, Exfiltration)

---
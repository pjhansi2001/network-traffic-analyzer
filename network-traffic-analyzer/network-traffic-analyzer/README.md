# 🔍 Network Traffic Analyzer

A Python application that analyzes network traffic logs, detects anomalies using **statistical analysis**, and generates comprehensive JSON reports. Built to demonstrate data pipeline engineering, anomaly detection, and analytical reporting skills.

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Python 3.10+ | Core language |
| Statistics module | Z-score anomaly detection |
| Collections / Counter | Frequency analysis |
| CSV / JSON | Data ingestion & reporting |
| Datetime | Timestamp processing |

## 🚀 Features

- ✅ Load real CSV traffic logs OR generate sample data
- ✅ Descriptive statistics (mean, median, std dev, min, max)
- ✅ **Z-Score statistical anomaly detection** (flags packets > mean + 2σ)
- ✅ Rule-based detection (privileged port scanning, RST flood detection)
- ✅ Protocol distribution analysis (TCP, UDP, HTTP, HTTPS, FTP, SSH)
- ✅ Top source/destination IP analysis
- ✅ Risk scoring for detected anomalies
- ✅ JSON report generation
- ✅ Text-based analytics dashboard

## 📋 How to Run

```bash
# Clone the repo
git clone https://github.com/pjhansi2001/network-traffic-analyzer.git
cd network-traffic-analyzer

# No external dependencies needed — uses Python standard library only!
python analyzer.py
```

## 📊 Sample Output

```
🔍 Network Traffic Analyzer

✅ Generated 500 sample traffic records

📊 Traffic Statistics:
   Total Records    : 500
   Avg Packet Size  : 842.3 bytes
   Std Dev (size)   : 612.7 bytes
   Avg Duration     : 1.2341 sec
   Protocol Mix     : {'TCP': 89, 'HTTP': 86, 'HTTPS': 84, ...}

🚨 Anomaly Detection Results:
   Total Anomalies  : 23
   Detection Rate   : 4.6%
   Detection Method : Z-Score + Rule-Based Analysis

✅ Report saved to network_traffic_report.json
✅ Analysis complete!
```

## 🧠 Anomaly Detection Method

Uses a **multi-layer detection approach:**

1. **Z-Score Analysis** — flags packets with size > mean + 2×stdev
2. **Port Scanning Detection** — identifies high-frequency access to privileged ports (<1024)
3. **RST Flood Detection** — flags RST flag packets with above-average size
4. **Risk Scoring** — each anomaly is scored (1–3) based on number of triggered rules

## 📁 Project Structure

```
network-traffic-analyzer/
├── analyzer.py          # Main analysis engine
├── requirements.txt     # Dependencies (standard library only)
├── sample_data/
│   └── sample_traffic.csv  # Example input data
└── README.md
```

## 👩‍💻 Author

**Jhansi Pinninti** — Software Engineer  
[LinkedIn](https://www.linkedin.com/in/jhansi-pinninti-a3a35b36a/) | [Portfolio](https://pjhansi2001.github.io/jhansi-pinninti.github.io/)

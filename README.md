# 🛡️ Real-Time Security Monitoring & Intrusion Detection System

A Python-based real-time network security monitoring system that captures live network traffic, detects suspicious activity, stores security alerts in SQLite, and displays them through a Streamlit dashboard.

## 🚀 Features

- Real-time network packet monitoring
- Port scan detection
- Excessive connection detection
- Security alert generation
- SQLite database for storing alerts
- Real-time Streamlit dashboard
- Automatic dashboard refresh
- Security event reporting

## 🛠️ Technologies Used

- Python
- Scapy
- SQLite
- Streamlit
- Pandas
- Git & GitHub

## 📁 Project Structure

```text
security-log-analyzer/
│
├── data/
│   └── security_events.db
│
├── src/
│   ├── main.py
│   ├── packet_monitor.py
│   ├── threat_detector.py
│   ├── database.py
│   └── test_detector.py
│
├── dashboard/
│   └── app.py
│
├── reports/
│   └── security_report.txt
│
├── README.md
├── requirements.txt
└── .gitignore
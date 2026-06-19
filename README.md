# Network Intrusion Detection System (NIDS)

A simple Python-based NIDS that detects SYN Floods, Port Scans, and ICMP Floods using Scapy.

## Setup

```bash
pip install -r requirements.txt
sudo python nids.py
```

## How it works

- Sniffs live network packets
- Detects **SYN Flood** — too many SYN packets from one IP
- Detects **Port Scan** — one IP hitting many different ports
- Detects **ICMP Flood** — too many ping packets from one IP
- Alerts are printed to console and saved to `alerts.log`

## Requirements

- Python 3.x
- Linux (root/sudo required for packet capture)
- Scapy

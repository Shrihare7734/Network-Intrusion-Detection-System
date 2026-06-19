Simple NIDS 

A lightweight Network Intrusion Detection System (NIDS) written in Python with Scapy. It passively sniffs live network traffic and raises alerts for common attack patterns — SYN floods, port scans, and ICMP floods — based on simple per-source counters and thresholds.

Built as a minimal, readable example of packet-level intrusion detection rather than a production-grade IDS.

Features


SYN Flood Detection — flags a source IP once it sends an unusually high number of TCP SYN packets
Port Scan Detection — flags a source IP once it has touched an unusually high number of unique destination ports
ICMP Flood Detection — flags a source IP once it sends an unusually high number of ICMP packets
Live console alerts with timestamps
Persistent logging to alerts.log for later review


How It Works

The script uses scapy.sniff() to capture packets in real time and passes each one to a handler that:


Checks for an IP layer (ignores non-IP traffic)
Tracks per-source counters for SYN packets, ICMP packets, and unique destination ports
Fires an alert the moment a counter crosses its configured threshold


DetectionThreshold (default)Trigger conditionSYN Flood100 packetsTCP packets with only the SYN flag setPort Scan15 unique portsDistinct destination ports from one sourceICMP Flood50 packetsICMP packets from one source

Thresholds are defined as constants at the top of nids.py and can be tuned to fit your network.

Requirements


Python 3.7+
Scapy
Root/administrator privileges (required for raw packet sniffing)


Install dependencies:

bashpip install scapy

Usage

Run with elevated privileges since raw packet capture requires it:

bashsudo python nids.py

You should see:

NIDS started — monitoring traffic... (Ctrl+C to stop)

When an attack pattern is detected, you'll see console output like:

[14:32:07]  SYN FLOOD | Source: 192.168.1.50 | Sent 100 SYN packets

All alerts are also appended to alerts.log in the working directory for later analysis.

Stop monitoring anytime with Ctrl+C.

Configuration

Adjust detection sensitivity by editing the constants at the top of nids.py:

pythonSYN_LIMIT   = 100   # SYN packets before alert
ICMP_LIMIT  = 50    # ICMP packets before alert
PORT_LIMIT  = 15    # Unique ports before alert

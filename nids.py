"""
Simple Network Intrusion Detection System
Uses Scapy to sniff packets and detect basic attacks.
Run with: sudo python nids.py
"""

from scapy.all import sniff, IP, TCP, ICMP
from collections import defaultdict
from datetime import datetime

# Thresholds
SYN_LIMIT   = 100   # SYN packets before alert
ICMP_LIMIT  = 50    # ICMP packets before alert
PORT_LIMIT  = 15    # Unique ports before alert

syn_count   = defaultdict(int)
icmp_count  = defaultdict(int)
port_track  = defaultdict(set)


def alert(attack, src, detail):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 {attack} | Source: {src} | {detail}")
    with open("alerts.log", "a") as f:
        f.write(f"{datetime.now()} | {attack} | {src} | {detail}\n")


def process_packet(pkt):
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src

    # SYN Flood detection
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        syn_count[src] += 1
        if syn_count[src] == SYN_LIMIT:
            alert("SYN FLOOD", src, f"Sent {syn_count[src]} SYN packets")

    # Port Scan detection
    if pkt.haslayer(TCP):
        port_track[src].add(pkt[TCP].dport)
        if len(port_track[src]) == PORT_LIMIT:
            alert("PORT SCAN", src, f"Scanned {len(port_track[src])} ports")

    # ICMP Flood detection
    if pkt.haslayer(ICMP):
        icmp_count[src] += 1
        if icmp_count[src] == ICMP_LIMIT:
            alert("ICMP FLOOD", src, f"Sent {icmp_count[src]} ICMP packets")


print("NIDS started — monitoring traffic... (Ctrl+C to stop)\n")
sniff(prn=process_packet, store=False)

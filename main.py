import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from src.database import init_db, get_connection
from src.detector import analyze_packet
from src.alerter import log_alert_to_file

def process_packet(packet):
    if not packet.haslayer(IP):
        return

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    length = len(packet)
    protocol = None
    src_port = None
    dst_port = None

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    # Log to database
    conn = get_connection()
    conn.execute('''
        INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length))
    conn.commit()
    conn.close()

    print(f"[{timestamp}] {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({length} bytes)")

    # Run detection
    if protocol in ("TCP", "UDP") and dst_port:
        analyze_packet(src_ip, dst_ip, protocol, dst_port)

if __name__ == "__main__":
    print("[*] Initializing database...")
    init_db()
    print("[*] Starting IDS — press Ctrl+C to stop")
    WIFI_INTERFACE = r"\Device\NPF_{6837E140-D80A-450D-AAAF-52C611E3E5B8}"
    sniff(iface=WIFI_INTERFACE, prn=process_packet, store=False)
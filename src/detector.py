from datetime import datetime
from collections import defaultdict
from src.database import get_connection

# Thresholds
PORT_SCAN_THRESHOLD = 10    # unique ports in time window
BRUTE_FORCE_THRESHOLD = 5   # connections to same port in time window
TIME_WINDOW = 60            # seconds

# In-memory trackers
port_scan_tracker = defaultdict(set)       # src_ip -> set of dst_ports
brute_force_tracker = defaultdict(int)     # (src_ip, dst_port) -> count

def save_alert(alert_type, severity, src_ip, dst_ip, description):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_connection()
    conn.execute('''
        INSERT INTO alerts (timestamp, alert_type, severity, src_ip, dst_ip, description)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, alert_type, severity, src_ip, dst_ip, description))
    conn.commit()
    conn.close()
    print(f"[ALERT] [{severity}] {alert_type} — {description}")

def analyze_packet(src_ip, dst_ip, protocol, dst_port):
    if protocol not in ("TCP", "UDP"):
        return

    # Port scan detection
    port_scan_tracker[src_ip].add(dst_port)
    if len(port_scan_tracker[src_ip]) >= PORT_SCAN_THRESHOLD:
        save_alert(
            alert_type="PORT_SCAN",
            severity="HIGH",
            src_ip=src_ip,
            dst_ip=dst_ip,
            description=f"{src_ip} scanned {len(port_scan_tracker[src_ip])} unique ports"
        )
        port_scan_tracker[src_ip].clear()

    # Brute force detection
    if dst_port in (22, 3389, 21, 23):   # SSH, RDP, FTP, Telnet
        key = (src_ip, dst_port)
        brute_force_tracker[key] += 1
        if brute_force_tracker[key] >= BRUTE_FORCE_THRESHOLD:
            service = {22: "SSH", 3389: "RDP", 21: "FTP", 23: "Telnet"}.get(dst_port, str(dst_port))
            save_alert(
                alert_type="BRUTE_FORCE",
                severity="CRITICAL",
                src_ip=src_ip,
                dst_ip=dst_ip,
                description=f"{src_ip} made {brute_force_tracker[key]} attempts on {service}"
            )
            brute_force_tracker[key] = 0
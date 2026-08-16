from datetime import datetime
from src.database import get_connection

def get_recent_alerts(limit=50):
    conn = get_connection()
    alerts = conn.execute('''
        SELECT * FROM alerts
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return alerts

def get_alert_stats():
    conn = get_connection()

    total = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]

    critical = conn.execute(
        'SELECT COUNT(*) FROM alerts WHERE severity = "CRITICAL"'
    ).fetchone()[0]

    high = conn.execute(
        'SELECT COUNT(*) FROM alerts WHERE severity = "HIGH"'
    ).fetchone()[0]

    by_type = conn.execute('''
        SELECT alert_type, COUNT(*) as count
        FROM alerts
        GROUP BY alert_type
        ORDER BY count DESC
    ''').fetchall()

    conn.close()

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "by_type": [{"type": row[0], "count": row[1]} for row in by_type]
    }

def log_alert_to_file(alert_type, severity, src_ip, description):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] [{severity}] {alert_type} | {src_ip} | {description}\n"

    with open("logs/alerts.log", "a") as f:
        f.write(log_line)
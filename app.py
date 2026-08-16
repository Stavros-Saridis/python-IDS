from flask import Flask, render_template, jsonify
from src.database import init_db, get_connection
from src.alerter import get_recent_alerts, get_alert_stats

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alerts')
def api_alerts():
    alerts = get_recent_alerts(50)
    return jsonify([dict(a) for a in alerts])

@app.route('/api/stats')
def api_stats():
    return jsonify(get_alert_stats())

@app.route('/api/packets')
def api_packets():
    conn = get_connection()
    packets = conn.execute('''
        SELECT * FROM packets
        ORDER BY timestamp DESC
        LIMIT 100
    ''').fetchall()
    conn.close()
    return jsonify([dict(p) for p in packets])

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
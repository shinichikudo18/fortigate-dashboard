#!/usr/bin/env python3
"""
FortiGate Dashboard - Flask Web Application
Provides summary and per-branch views of FortiGate device status
"""

from flask import Flask, render_template, jsonify
from pathlib import Path
import json

app = Flask(__name__, 
            template_folder=Path(__file__).parent.parent / "templates",
            static_folder=Path(__file__).parent.parent / "static")

DATA_FILE = Path(__file__).parent.parent / "data" / "fortigate_status.json"

def load_data():
    """Load FortiGate data from JSON file"""
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"total_devices": 0, "online_devices": 0, "devices": []}

@app.route('/')
def index():
    """Main dashboard page - summary view"""
    data = load_data()
    return render_template('index.html', data=data)

@app.route('/api/summary')
def api_summary():
    """API endpoint for summary data"""
    data = load_data()
    return jsonify(data)

@app.route('/api/device/<ip>')
def api_device(ip):
    """API endpoint for specific device data"""
    data = load_data()
    device = next((d for d in data.get("devices", []) if d["ip"] == ip), None)
    if device:
        return jsonify(device)
    return jsonify({"error": "Device not found"}), 404

@app.route('/branch/<hostname>')
def branch_view(hostname):
    """Per-branch detailed view"""
    data = load_data()
    devices = [d for d in data.get("devices", []) if d.get("hostname") == hostname]
    return render_template('branch.html', hostname=hostname, devices=devices, data=data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)

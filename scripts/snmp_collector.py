#!/usr/bin/env python3
"""
FortiGate SNMP Collector
Collects data from FortiGate devices via SNMP and stores in JSON format
Uses threading for parallel collection
"""

import json
import time
import subprocess
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
FORTIGATE_IPS = [f"193.168.100.{i}" for i in range(2, 30)] + ["193.168.100.250"]
SNMP_COMMUNITY = "public"
SNMP_VERSION = "2c"
MIBS_DIR = Path(__file__).parent.parent / "mibs"
DATA_DIR = Path(__file__).parent.parent / "data"
OUTPUT_FILE = DATA_DIR / "fortigate_status.json"

# OIDs for FortiGate monitoring
OIDS = {
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "fgProcessorUsage": "1.3.6.1.4.1.12356.101.4.1.3.0",
    "fgMemoryUsage": "1.3.6.1.4.1.12356.101.4.1.4.0",
    "fgDiskUsage": "1.3.6.1.4.1.12356.101.4.1.6.0",
    "fgCurrentSessions": "1.3.6.1.4.1.12356.101.4.1.8.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
}

def snmp_get(ip, oid, community=SNMP_COMMUNITY):
    """Execute SNMP GET request using snmpget command"""
    try:
        cmd = [
            "snmpget",
            "-v", SNMP_VERSION,
            "-c", community,
            "-t", "3",
            "-r", "0",
            ip,
            oid
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            output = result.stdout.strip()
            if "=" in output:
                value_part = output.split("=")[1].strip()
                for prefix in ["STRING: ", "INTEGER: ", "Timeticks: ", "Gauge32: "]:
                    if value_part.startswith(prefix):
                        value_part = value_part[len(prefix):].strip()
                        break
                if value_part.startswith('"') and value_part.endswith('"'):
                    value_part = value_part[1:-1]
                return value_part
        return None
    except Exception as e:
        return None

def collect_device_data(ip):
    """Collect all SNMP data from a single device"""
    device_data = {
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "status": "unreachable"
    }
    
    sys_name = snmp_get(ip, OIDS["sysName"])
    if sys_name is None:
        return device_data
    
    device_data["status"] = "online"
    device_data["hostname"] = sys_name
    
    for key, oid in OIDS.items():
        if key == "sysName":
            device_data[key] = sys_name
        else:
            value = snmp_get(ip, oid)
            if value is not None:
                if key in ["fgProcessorUsage", "fgMemoryUsage", "fgDiskUsage", "fgCurrentSessions"]:
                    try:
                        device_data[key] = int(value)
                    except:
                        device_data[key] = value
                else:
                    device_data[key] = value
    
    return device_data

def main():
    """Main collection function"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    print(f"Starting SNMP collection at {datetime.now().isoformat()}")
    print(f"Target devices: {len(FORTIGATE_IPS)}")
    
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(collect_device_data, ip): ip for ip in FORTIGATE_IPS}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                data = future.result()
                results.append(data)
                print(f"Collected from {ip}: {data['status']}")
            except Exception as exc:
                print(f"Error collecting from {ip}: {exc}")
                results.append({"ip": ip, "status": "error", "timestamp": datetime.now().isoformat()})
    
    output = {
        "collection_time": datetime.now().isoformat(),
        "total_devices": len(FORTIGATE_IPS),
        "online_devices": sum(1 for d in results if d["status"] == "online"),
        "devices": results
    }
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\nCollection complete!")
    print(f"Total: {output['total_devices']}, Online: {output['online_devices']}")
    print(f"Data saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

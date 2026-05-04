#!/usr/bin/env python3
"""
FortiGate SNMP Collector
Collects data from FortiGate devices via SNMP and stores in JSON format
Uses threading for parallel collection
Includes: faceplate info, model/firmware, real-time interface BW
"""

import json
import time
import subprocess
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
FORTIGATE_IPS = [f"193.168.100.{i}" for i in range(2, 30)] + ["193.168.100.250"]
SNMP_COMMUNITY = "Agnov"
SNMP_VERSION = "2c"
MIBS_DIR = Path(__file__).parent.parent / "mibs"
DATA_DIR = Path(__file__).parent.parent / "data"
OUTPUT_FILE = DATA_DIR / "fortigate_status.json"
INTERFACE_FILE = DATA_DIR / "interface_stats.json"

# OIDs for FortiGate monitoring
OIDS = {
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "fgProcessorUsage": "1.3.6.1.4.1.12356.101.4.1.3.0",
    "fgMemoryUsage": "1.3.6.1.4.1.12356.101.4.1.4.0",
    "fgDiskUsage": "1.3.6.1.4.1.12356.101.4.1.6.0",
    "fgCurrentSessions": "1.3.6.1.4.1.12356.101.4.1.8.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "fgFirmware": "1.3.6.1.4.1.12356.101.4.1.1.0",
    "fgModel": "1.3.6.1.2.1.1.1.0",  # Use sysDescr for model info
    # SD-WAN SLA OIDs (fgLinkMonitorTable - walk these)
    "fgLinkMonitorTable": "1.3.6.1.4.1.12356.101.10.2.2",
    # FortiSwitch OIDs
    "fgSwitchModel": "1.3.6.1.4.1.12356.2.1.1.0",  # Example, verify in MIB
}
}

    # Interface OIDs
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",  # Interface description
    "ifType": "1.3.6.1.2.1.2.2.1.3",
    "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
    "ifName": "1.3.6.1.2.1.2.2.1.2",  # Interface name
    # FortiSwitch OIDs (same MIB)
    "fgSwitchModel": "1.3.6.1.4.1.12356.2.1.1.0",  # Example, may need adjustment
}
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

def snmp_walk(ip, oid, community=SNMP_COMMUNITY):
    """Execute SNMP WALK request and return dict of {index: value}"""
    results = {}
    try:
        cmd = [
            "snmpwalk",
            "-v", SNMP_VERSION,
            "-c", community,
            "-t", "3",
            "-r", "0",
            ip,
            oid
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if "=" in line:
                    parts = line.split("=")
                    oid_part = parts[0].strip()
                    value_part = parts[1].strip()
                    for prefix in ["STRING: ", "INTEGER: ", "Gauge32: ", "Counter32: ", "Counter64: "]:
                        if value_part.startswith(prefix):
                            value_part = value_part[len(prefix):].strip()
                            break
                    if value_part.startswith('"') and value_part.endswith('"'):
                        value_part = value_part[1:-1]
                    oid_index = oid_part.split(".")[-1] if "." in oid_part else "0"
                    results[oid_index] = value_part
        return results
    except Exception as e:
        return results

def collect_interface_data(ip):
    """Collect interface statistics for bandwidth calculation"""
    interfaces = {}
    
    # Get interface names and descriptions
    if_names = snmp_walk(ip, IF_OIDS["ifName"])
    if_descrs = snmp_walk(ip, IF_OIDS["ifDescr"])
    
    # Get interface speeds
    if_speeds = snmp_walk(ip, IF_OIDS["ifSpeed"])
    # Get interface statuses
    if_statuses = snmp_walk(ip, IF_OIDS["ifOperStatus"])
    # Get interface octets (for bandwidth calculation)
    if_in_octets = snmp_walk(ip, IF_OIDS["ifInOctets"])
    if_out_octets = snmp_walk(ip, IF_OIDS["ifOutOctets"])
    
    # Use if_names keys, but if empty use if_descrs keys
    all_idx = set(if_names.keys()) | set(if_descrs.keys())
    
    for idx in all_idx:
        name = if_names.get(idx, "")
        descr = if_descrs.get(idx, "")
        # Prefer name, fallback to descr, fallback to if{idx}
        display_name = name if name else (descr if descr else f"if{idx}")
        # Clean up name: remove quotes, extra spaces
        display_name = display_name.strip().strip('"').strip("'")
        if not display_name:
            display_name = f"Interface {idx}"
        
        speed = if_speeds.get(idx, "0")
        status = if_statuses.get(idx, "2")
        in_octets = if_in_octets.get(idx, "0")
        out_octets = if_out_octets.get(idx, "0")
        
        try:
            speed_val = int(speed)
        except:
            speed_val = 0
        
        try:
            in_octets_val = int(in_octets)
            out_octets_val = int(out_octets)
        except:
            in_octets_val = 0
            out_octets_val = 0
        
        interfaces[idx] = {
            "name": display_name,
            "description": descr.strip().strip('"').strip("'") if descr else "",
            "speed": speed_val,
            "speed_human": f"{speed_val // 1000000} Mbps" if speed_val > 0 else "Unknown",
            "status": "up" if status == "1" else "down",
            "in_octets": in_octets_val,
            "out_octets": out_octets_val,
            "timestamp": time.time()
        }
    
    return interfaces

def format_bandwidth(bps):
    """Format bandwidth in human readable format"""
    if bps < 1000:
        return f"{bps:.1f} bps"
    elif bps < 1000000:
        return f"{bps/1000:.1f} Kbps"
    elif bps < 1000000000:
        return f"{bps/1000000:.1f} Mbps"
    else:
        return f"{bps/1000000000:.1f} Gbps"

def calculate_bandwidth(current_stats, previous_stats):
    """Calculate real-time bandwidth from two data points"""
    bw_data = {}
    
    for idx in current_stats.keys():
        if idx in previous_stats:
            curr = current_stats[idx]
            prev = previous_stats[idx]
            
            time_diff = curr["timestamp"] - prev["timestamp"]
            if time_diff <= 0:
                time_diff = 1
            
            in_diff = curr["in_octets"] - prev["in_octets"]
            out_diff = curr["out_octets"] - prev["out_octets"]
            
            if in_diff < 0:
                in_diff += 2**32
            if out_diff < 0:
                out_diff += 2**32
            
            in_bps = (in_diff * 8) / time_diff
            out_bps = (out_diff * 8) / time_diff
            
            bw_data[idx] = {
                "name": curr["name"],
                "in_bps": in_bps,
                "out_bps": out_bps,
                "in_human": format_bandwidth(in_bps),
                "out_human": format_bandwidth(out_bps),
                "status": curr["status"],
                "speed": curr["speed_human"]
            }
    
    return bw_data

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
                elif key == "fgFirmware":
                    device_data["firmware"] = value
                elif key == "sysDescr":
                    device_data["sysDescr"] = value
                    # Parse model from description
                    if "FortiGate" in value or "Fortigate" in value:
                        parts = value.split()
                        if len(parts) > 0:
                            device_data["model"] = parts[0]
                elif key == "fgFirmware":
                    device_data["firmware"] = value
                elif key == "fgSwitchModel":
                    # FortiSwitch model
                    device_data["switch_model"] = value
                elif key.startswith("fgSdwan"):
                    # Handle SD-WAN SLA metrics
                    pass
                else:
                    device_data[key] = value
    
    interfaces = collect_interface_data(ip)
    device_data["interfaces"] = interfaces
    
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
    
    previous_stats = {}
    if INTERFACE_FILE.exists():
        try:
            with open(INTERFACE_FILE, 'r') as f:
                previous_stats = json.load(f)
        except:
            pass
    
    current_stats = {}
    for device in results:
        if device.get("status") == "online" and "interfaces" in device:
            current_stats[device["ip"]] = device["interfaces"]
            
            if device["ip"] in previous_stats:
                bw_data = calculate_bandwidth(device["interfaces"], previous_stats[device["ip"]])
                device["bandwidth"] = bw_data
    
    with open(INTERFACE_FILE, 'w') as f:
        json.dump(current_stats, f, indent=2)
    
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

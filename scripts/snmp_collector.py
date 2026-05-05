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
BW_HISTORY_FILE = DATA_DIR / "bw_history.json"

# API Keys for all branches with API access
API_KEYS = {
    "193.168.100.2": "3h9574d48tN36HQ1N77Q5r0j0tpnG5",
    "193.168.100.3": "013GwtQq4nr4m06xxnx6dmwQyQ0s7r",
    "193.168.100.4": "fht819gy6bgg98gzk5ts4165t5pNxb",
    "193.168.100.5": "0psxbQ6mbyx7b5cQGnHdkm3hQ9377w",
    "193.168.100.6": "n9pzhhrt1hN3rcw1Qjj3r7ptrj5ppQ",
    "193.168.100.7": "xzwwQ5w3bx10gb1Nh6gtQrjp4gyQ0w",
    "193.168.100.8": "H0bQc6gpjdnQQ7jgz1tmk1H8bq13Hg",
    "193.168.100.9": "75Nn8h9Hk18xpQdhrrk6n480kh0n16",
    "193.168.100.10": "m01430cNG3Nx83683scG7pNGmfhzc6",
    "193.168.100.11": "zns7j4ty55r7c9c9tpz6t4N47xpd14",
    "193.168.100.12": "kt4d5frkH6nkgsbgcc0HNsQ41f533b",
    "193.168.100.13": "gck91mcqyd0G6tjmgk5gnt8z6kqk9y",
    "193.168.100.14": "kHdHm6zctr61bwpzNfnjyrnNN4N3wn",
    "193.168.100.15": "ktkHgr7mg1ymyktqqj04z5cd35N3kQ",
    "193.168.100.16": "c8fGHynjdw4cfcbtz81QgmGzjdQ9Gn",
    "193.168.100.17": "nt6zqfk6p9311QwnHf7qbbxc53sGts",
    "193.168.100.18": "mhhwnkc7t3r1Gm8by7HxtnxGGsQg0n",
    "193.168.100.19": "7wpG33347QN4pH6t7ksgG0746xjQNh",
    "193.168.100.20": "sgQddf470gq59dq4rdNt9ghyqnsxfy",
    "193.168.100.22": "jwNbdrwG4bjz3N6z7xnbcq5wy7H3kt",
    "193.168.100.23": "tbsxsms4p1t9ktbGdkdQ40zkyfc7Hq",
    "193.168.100.24": "q7hgbs37gn60fgQjGhjc75jzyQ131w",
    "193.168.100.25": "fQxzhkngdw9f0w03d1mmmtt3pcjyj1",
    "193.168.100.26": "p86b1wx95x1h5fqQzjkygzk3c0N1bg",
    "193.168.100.27": "gdQ1Qd87Q5xrchyy8G11tqzwysgqdN",
    "193.168.100.28": "bntk4gqNhmwQsHH48rh16sQtqzkp61",
    "193.168.100.29": "qN170gHz73991wn5j0kcmgGnm0Ns4Q",
    "193.168.100.250": "HmdbzyspHHj96sk97jb35n36cjfbht",
}

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
    # SD-WAN Health Check OIDs (fgVWLHealthCheckLink table)
    "fgVWLHealthCheckStatus": "1.3.6.1.4.1.12356.101.4.9.2.1.4",  # Status per link
    "fgVWLHealthCheckLatency": "1.3.6.1.4.1.12356.101.4.9.2.1.5",  # Latency per link
    "fgVWLHealthCheckLoss": "1.3.6.1.4.1.12356.101.4.9.2.1.9",  # Packet loss per link
}

# Interface OIDs
IF_OIDS = {
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifType": "1.3.6.1.2.1.2.2.1.3",
    "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
    "ifName": "1.3.6.1.2.1.2.2.1.2",
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
    """Execute SNMP WALK request and return list of (index, value) tuples"""
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
                    # Extract index from oid
                    oid_index = oid_part.split(".")[-1] if "." in oid_part else "0"
                    results[oid_index] = value_part
        return results
    except Exception as e:
        return results

def parse_model_firmware(sys_descr):
    """Parse sysDescr to extract model and firmware version"""
    if not sys_descr:
        return "Unknown", "Unknown"
    
    # Example: FortiGate-60E v6.2.5,build1129,191209
    parts = sys_descr.split()
    model = "Unknown"
    firmware = "Unknown"
    
    for i, part in enumerate(parts):
        if "FortiGate" in part or "FG" in part:
            if i + 1 < len(parts):
                model = part + " " + parts[i+1] if i+1 < len(parts) else part
            else:
                model = part
        if "v" in part and "." in part:
            firmware = part.rstrip(',')
            break
    
    if model == "Unknown" and len(parts) > 0:
        model = parts[0]
    
    return model.strip(), firmware.strip()

def collect_interface_data(ip):
    """Collect interface statistics for bandwidth calculation"""
    interfaces = {}
    
    # Get interface descriptions/names
    if_names = snmp_walk(ip, IF_OIDS["ifName"])
    if not if_names:
        if_names = snmp_walk(ip, IF_OIDS["ifDescr"])
    
    # Get interface speeds
    if_speeds = snmp_walk(ip, IF_OIDS["ifSpeed"])
    
    # Get interface statuses
    if_statuses = snmp_walk(ip, IF_OIDS["ifOperStatus"])
    
    # Get interface octets (for bandwidth calculation)
    if_in_octets = snmp_walk(ip, IF_OIDS["ifInOctets"])
    if_out_octets = snmp_walk(ip, IF_OIDS["ifOutOctets"])
    
    for idx in if_names.keys():
        name = if_names.get(idx, f"if{idx}")
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
            "name": name,
            "speed": speed_val,
            "speed_human": f"{speed_val // 1000000} Mbps" if speed_val > 0 else "Unknown",
            "status": "up" if status == "1" else "down",
            "in_octets": in_octets_val,
            "out_octets": out_octets_val,
            "timestamp": time.time()
        }
    
    return interfaces

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
            
            # Handle counter wrap (32-bit)
            if in_diff < 0:
                in_diff += 2**32
            if out_diff < 0:
                out_diff += 2**32
            
            # Calculate bps (octets to bits)
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
    
    # Collect system info
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
                elif key == "sysDescr":
                    device_data[key] = value
                    model, firmware = parse_model_firmware(value)
                    device_data["model"] = model
                    device_data["firmware"] = firmware
                else:
                    device_data[key] = value
    
    # Collect interface data for bandwidth
    interfaces = collect_interface_data(ip)
    device_data["interfaces"] = interfaces
    
    # Collect SD-WAN SLA data (health check status, latency, packet loss)
    sla_status = snmp_walk(ip, OIDS["fgVWLHealthCheckStatus"])
    sla_latency = snmp_walk(ip, OIDS["fgVWLHealthCheckLatency"])
    sla_loss = snmp_walk(ip, OIDS["fgVWLHealthCheckLoss"])
    
    if sla_status or sla_latency or sla_loss:
        device_data["sla"] = {}
        # Get all unique SLA indices
        all_indices = set()
        if sla_status:
            all_indices.update(sla_status.keys())
        if sla_latency:
            all_indices.update(sla_latency.keys())
        if sla_loss:
            all_indices.update(sla_loss.keys())
        
        for idx in sorted(all_indices):
            status = sla_status.get(idx, "1") if sla_status else "1"
            latency = sla_latency.get(idx, "0") if sla_latency else "0"
            loss = sla_loss.get(idx, "0") if sla_loss else "0"
            
            try:
                lat_val = float(latency)
            except:
                lat_val = 0
            try:
                loss_val = float(loss)
            except:
                loss_val = 0
            
            device_data["sla"][f"wan{idx}"] = {
                "status": "up" if status == "0" else "down",
                "latency_ms": lat_val,
                "packet_loss": loss_val
            }
    
    # Try API connection for branches with API keys
    if ip in API_KEYS:
        try:
            import requests
            api_key = API_KEYS[ip]
            headers = {"Authorization": f"Bearer {api_key}"}
            
            # Collect multiple API endpoints
            api_endpoints = {
                "system_status": "/api/v2/monitor/system/status",
                "interfaces": "/api/v2/monitor/system/interface",
                "sdwan_health": "/api/v2/monitor/sdwan/health-check",
                "vpn_tunnels": "/api/v2/monitor/vpn/ipsec",
                "firewall_sessions": "/api/v2/monitor/firewall/session",
                "system_resources": "/api/v2/monitor/system/resources/used",
            }
            
            device_data["api_status"] = "connected"
            device_data["api_data"] = {}
            
            for ep_name, ep_path in api_endpoints.items():
                try:
                    response = requests.get(f"https://{ip}{ep_path}", headers=headers, verify=False, timeout=5)
                    if response.status_code == 200:
                        device_data["api_data"][ep_name] = response.json()
                except:
                    pass
            
            # Extract useful data from API responses
            if "system_status" in device_data["api_data"]:
                sys_info = device_data["api_data"]["system_status"].get("results", {})
                device_data["api_hostname"] = sys_info.get("hostname", "")
                device_data["api_version"] = sys_info.get("version", "")
                device_data["api_serial"] = sys_info.get("serial", "")
            
            if "sdwan_health" in device_data["api_data"]:
                sdwan_data = device_data["api_data"]["sdwan_health"].get("results", [])
                if sdwan_data:
                    device_data["sla"] = {}
                    for sla in sdwan_data:
                        sla_name = sla.get("name", "unknown")
                        device_data["sla"][sla_name] = {
                            "status": "up" if sla.get("status", 0) == 1 else "down",
                            "latency_ms": sla.get("latency", 0),
                            "packet_loss": sla.get("packet_loss", 0)
                        }
            
        except Exception as e:
            device_data["api_status"] = f"error: {str(e)}"
    
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
    
    # Load previous interface stats for bandwidth calculation
    previous_stats = {}
    if INTERFACE_FILE.exists():
        try:
            with open(INTERFACE_FILE, 'r') as f:
                previous_stats = json.load(f)
        except:
            pass
    
    # Calculate bandwidth for each device
    current_stats = {}
    for device in results:
        if device.get("status") == "online" and "interfaces" in device:
            current_stats[device["ip"]] = device["interfaces"]
            
            if device["ip"] in previous_stats:
                bw_data = calculate_bandwidth(device["interfaces"], previous_stats[device["ip"]])
                device["bandwidth"] = bw_data
    
    # Save current interface stats for next calculation
    with open(INTERFACE_FILE, 'w') as f:
        json.dump(current_stats, f, indent=2)
    
    # Save results
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

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
    # SD-WAN SLA OIDs (fgLinkMonitorTable)
    "fgLinkMonitorTable": "1.3.6.1.4.1.12356.101.10.2.2",
}

# Interface OIDs
IF_OIDS = {
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",  # Interface description
    "ifType": "1.3.6.1.2.1.2.2.1.3",
    "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
    "ifName": "1.3.6.1.2.1.2.2.1.2",  # Interface name
}

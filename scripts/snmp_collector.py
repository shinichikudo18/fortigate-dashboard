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

def classify_threat(response):
    threat = response.get("threat_data", {})
    vt = threat.get("virustotal", {})
    abuse = threat.get("abuseipdb", {})
    nmap = threat.get("nmap", {})
    cves = threat.get("cves", [])

    categories = []
    reasons = []
    confidence = 40

    if isinstance(vt, dict) and vt.get("malicious", 0) > 0:
        categories.append("Suspicious Reputation")
        reasons.append(f"Detected by {vt.get('malicious')} VirusTotal engines")
        confidence += 20

    if isinstance(abuse, dict) and abuse.get("abuse_confidence_score", 0) >= 10:
        categories.append("Reported Abuse Source")
        reasons.append(f"AbuseIPDB score is {abuse.get('abuse_confidence_score')}")
        confidence += 15

    if isinstance(nmap, dict):
        ports = [p.get("port") for p in nmap.get("open_ports", [])]
        if 22 in ports:
            categories.append("Remote Access Exposure")
            reasons.append("SSH port 22 is exposed")
            confidence += 10
        if 80 in ports or 443 in ports:
            categories.append("Internet-Facing Web Server")
            reasons.append("HTTP/HTTPS service is exposed")
            confidence += 10

    outdated = []
    for item in cves if isinstance(cves, list) else []:
        vs = item.get("version_status", {})
        if vs.get("update_required") is True:
            outdated.append(item.get("product"))

    if outdated:
        categories.append("Outdated Service")
        reasons.append(f"Outdated services detected: {', '.join(outdated)}")
        confidence += 15

    confidence = min(confidence, 100)

    return {
        "categories": list(dict.fromkeys(categories)) or ["Low Signal IOC"],
        "confidence": f"{confidence}%",
        "reasons": reasons or ["No strong malicious classification indicators found"],
        "final_label": "High Confidence Suspicious" if confidence >= 75 else "Suspicious" if confidence >= 55 else "Monitor"
    }

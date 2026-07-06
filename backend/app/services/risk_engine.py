def calculate_risk_score(vt_result, abuse_result, nmap_result=None, cve_result=None, mitre_result=None):
    score = 0
    reasons = []

    # VirusTotal
    if isinstance(vt_result, dict):
        malicious = vt_result.get("malicious", 0)
        suspicious = vt_result.get("suspicious", 0)

        if malicious >= 10:
            score += 30
            reasons.append("High VirusTotal malicious detections")
        elif malicious >= 3:
            score += 20
            reasons.append("Medium VirusTotal malicious detections")
        elif malicious >= 1:
            score += 10
            reasons.append("Low VirusTotal malicious detections")

        if suspicious >= 5:
            score += 10
            reasons.append("Suspicious detections found on VirusTotal")

    # AbuseIPDB
    if isinstance(abuse_result, dict):
        abuse_score = abuse_result.get("abuse_confidence_score", 0)
        total_reports = abuse_result.get("total_reports", 0)

        if abuse_score >= 90:
            score += 40
            reasons.append("Very high AbuseIPDB confidence score")
        elif abuse_score >= 50:
            score += 25
            reasons.append("High AbuseIPDB confidence score")
        elif abuse_score >= 10:
            score += 10
            reasons.append("Low AbuseIPDB abuse confidence score")

        if total_reports and total_reports > 50 and abuse_score >= 10:
            score += 10
            reasons.append("High number of abuse reports with abuse confidence")

    # Nmap risky ports
    risky_ports = {
        21: "FTP exposed",
        22: "SSH exposed",
        23: "Telnet exposed",
        445: "SMB exposed",
        3389: "RDP exposed",
        3306: "MySQL exposed",
        5432: "PostgreSQL exposed",
        6379: "Redis exposed"
    }

    if isinstance(nmap_result, dict):
        for port_info in nmap_result.get("open_ports", []):
            port = port_info.get("port")
            if port in risky_ports:
                score += 10
                reasons.append(risky_ports[port])

    # CVE severity
    if isinstance(cve_result, list):
        for item in cve_result:
            for cve in item.get("cves", []):
                severity = str(cve.get("severity", "")).lower()
                cvss = cve.get("cvss_score") or 0

                if severity == "critical" or cvss >= 9:
                    score += 30
                    reasons.append(f"Critical CVE detected: {cve.get('cve_id')}")
                elif severity == "high" or cvss >= 7:
                    score += 20
                    reasons.append(f"High severity CVE detected: {cve.get('cve_id')}")
                elif severity == "medium" or cvss >= 4:
                    score += 10
                    reasons.append(f"Medium severity CVE detected: {cve.get('cve_id')}")

    # MITRE mapping
    if isinstance(mitre_result, list) and len(mitre_result) >= 3:
        score += 10
        reasons.append("Multiple MITRE ATT&CK techniques mapped")

    score = min(score, 100)

    if score >= 75:
        severity = "Critical"
    elif score >= 50:
        severity = "High"
    elif score >= 25:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "score": score,
        "severity": severity,
        "reasons": reasons if reasons else ["No major risk indicators found"]
    }

def build_cve_summary(cve_result):
    summary = {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0
    }

    if not isinstance(cve_result, list):
        return summary

    for item in cve_result:
        for cve in item.get("cves", []):
            if cve.get("error"):
                continue

            summary["total"] += 1
            severity = str(cve.get("severity", "unknown")).lower()

            if severity in summary:
                summary[severity] += 1
            else:
                summary["unknown"] += 1

    return summary


def build_confidence_breakdown(response):
    threat = response.get("threat_data", {})
    vt = threat.get("virustotal", {})
    abuse = threat.get("abuseipdb", {})
    nmap = threat.get("nmap", {})
    cves = threat.get("cves", [])
    mitre = threat.get("mitre_attack", [])

    breakdown = {
        "virustotal": 0,
        "abuseipdb": 0,
        "network_exposure": 0,
        "cve_intelligence": 0,
        "mitre_mapping": 0
    }

    if isinstance(vt, dict):
        malicious = vt.get("malicious", 0)
        if malicious >= 10:
            breakdown["virustotal"] = 30
        elif malicious >= 3:
            breakdown["virustotal"] = 22
        elif malicious >= 1:
            breakdown["virustotal"] = 10

    if isinstance(abuse, dict):
        score = abuse.get("abuse_confidence_score", 0)
        if score >= 90:
            breakdown["abuseipdb"] = 25
        elif score >= 50:
            breakdown["abuseipdb"] = 18
        elif score >= 10:
            breakdown["abuseipdb"] = 10

    if isinstance(nmap, dict):
        ports = [p.get("port") for p in nmap.get("open_ports", [])]
        if ports:
            breakdown["network_exposure"] = 10
        if 22 in ports or 445 in ports or 3389 in ports:
            breakdown["network_exposure"] += 10

    if isinstance(cves, list):
        for item in cves:
            for cve in item.get("cves", []):
                severity = str(cve.get("severity", "")).lower()
                cvss = cve.get("cvss_score") or 0

                if severity == "critical" or cvss >= 9:
                    breakdown["cve_intelligence"] = max(breakdown["cve_intelligence"], 25)
                elif severity == "high" or cvss >= 7:
                    breakdown["cve_intelligence"] = max(breakdown["cve_intelligence"], 18)
                elif severity == "medium" or cvss >= 4:
                    breakdown["cve_intelligence"] = max(breakdown["cve_intelligence"], 10)

    if isinstance(mitre, list):
        if len(mitre) >= 5:
            breakdown["mitre_mapping"] = 15
        elif len(mitre) >= 3:
            breakdown["mitre_mapping"] = 10
        elif len(mitre) > 0:
            breakdown["mitre_mapping"] = 5

    total = min(sum(breakdown.values()), 100)

    return {
        "overall_confidence": total,
        "breakdown": breakdown,
        "explanation": [
            f"VirusTotal contribution: {breakdown['virustotal']}",
            f"AbuseIPDB contribution: {breakdown['abuseipdb']}",
            f"Network exposure contribution: {breakdown['network_exposure']}",
            f"CVE intelligence contribution: {breakdown['cve_intelligence']}",
            f"MITRE mapping contribution: {breakdown['mitre_mapping']}"
        ]
    }

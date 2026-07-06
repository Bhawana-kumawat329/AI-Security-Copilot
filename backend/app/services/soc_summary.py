from app.services.action_playbook import generate_action_playbooks
def build_soc_summary(investigation):
    ioc = investigation.get("ioc")
    ioc_type = investigation.get("ioc_type")
    risk = investigation.get("risk", {})
    threat_data = investigation.get("threat_data", {})

    severity = risk.get("severity", "Unknown")
    score = risk.get("score", 0)
    reasons = risk.get("reasons", [])

    vt = threat_data.get("virustotal", {})
    abuse = threat_data.get("abuseipdb", {})
    nmap = threat_data.get("nmap", {})
    cves = threat_data.get("cves", [])
    mitre = threat_data.get("mitre_attack", [])
    geoip = threat_data.get("geoip", {})

    actions = []
    observations = []

    if isinstance(vt, dict):
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)

        if malicious > 0:
            observations.append(f"VirusTotal shows {malicious} malicious detection(s).")
            actions.append("Verify the IOC reputation using multiple threat intelligence sources.")

        if suspicious > 0:
            observations.append(f"VirusTotal shows {suspicious} suspicious detection(s).")

    if isinstance(abuse, dict):
        abuse_score = abuse.get("abuse_confidence_score", 0)
        reports = abuse.get("total_reports", 0)

        if abuse_score >= 50:
            observations.append(f"AbuseIPDB confidence score is high: {abuse_score}.")
            actions.append("Block or restrict traffic from this IP at firewall level.")
        elif abuse_score >= 10:
            observations.append(f"AbuseIPDB shows low-to-medium abuse confidence: {abuse_score}.")
            actions.append("Monitor logs for repeated connection attempts from this IP.")

        if reports:
            observations.append(f"AbuseIPDB has {reports} total report(s) for this IP.")

    if isinstance(geoip, dict):
        country = geoip.get("country")
        isp = geoip.get("isp")
        if country or isp:
            observations.append(f"GeoIP indicates location/ISP: {country or 'Unknown'} / {isp or 'Unknown'}.")

    open_ports = []
    if isinstance(nmap, dict):
        for port_info in nmap.get("open_ports", []):
            port = port_info.get("port")
            service = port_info.get("service")
            product = port_info.get("product")
            version = port_info.get("version")

            label = f"{port}/{service}"
            if product:
                label += f" ({product} {version})".strip()

            open_ports.append(label)

            if port == 22:
                actions.append("Restrict SSH access using firewall/VPN and disable password-based login.")
            if port == 3389:
                actions.append("Restrict RDP exposure and enforce MFA.")
            if port == 445:
                actions.append("Block public SMB exposure and review lateral movement risk.")
            if port in [80, 443]:
                actions.append("Review web server configuration, headers, and exposed application surface.")

        if open_ports:
            observations.append("Open services detected: " + ", ".join(open_ports[:8]) + ".")

    critical_cves = []
    high_cves = []

    if isinstance(cves, list):
        for item in cves:
            for cve in item.get("cves", []):
                severity_value = str(cve.get("severity", "")).lower()
                cve_id = cve.get("cve_id")

                if severity_value == "critical":
                    critical_cves.append(cve_id)
                elif severity_value == "high":
                    high_cves.append(cve_id)

    if critical_cves:
        observations.append(f"Critical CVEs detected: {', '.join(critical_cves[:5])}.")
        actions.append("Prioritize immediate patching or mitigation for critical CVEs.")

    if high_cves:
        observations.append(f"High severity CVEs detected: {', '.join(high_cves[:5])}.")
        actions.append("Plan urgent patching for high severity vulnerabilities.")

    if isinstance(mitre, list) and mitre:
        techniques = [f"{m.get('technique_id')} - {m.get('technique_name')}" for m in mitre[:5]]
        observations.append("Mapped MITRE ATT&CK techniques: " + ", ".join(techniques) + ".")

    if severity in ["Critical", "High"]:
        priority = "Immediate Investigation"
    elif severity == "Medium":
        priority = "Investigate Soon"
    else:
        priority = "Monitor"

    if not observations:
        observations.append("No major suspicious indicators were found from available sources.")

    if not actions:
        actions.append("No immediate blocking action required; continue monitoring.")

    summary = (
        f"The IOC {ioc} ({ioc_type}) is classified as {severity} risk "
        f"with a score of {score}/100. "
        f"Key reasons: {', '.join(reasons)}."
    )
    playbooks = generate_action_playbooks(investigation)

    return {
        "summary": summary,
        "priority": priority,
        "key_observations": observations,
        "recommended_actions": list(dict.fromkeys(actions)),
        "playbooks": playbooks,
        "analyst_verdict": f"{severity} risk - {priority}"

}

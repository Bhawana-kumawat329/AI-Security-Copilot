def generate_executive_verdict(response):
    ioc = response.get("ioc")
    ioc_type = response.get("ioc_type")
    risk = response.get("risk", {})
    threat = response.get("threat_data", {})
    classification = response.get("threat_classification", {})
    attack_surface = response.get("attack_surface", [])

    severity = risk.get("severity", "Unknown")
    score = risk.get("score", 0)

    vt = threat.get("virustotal", {})
    abuse = threat.get("abuseipdb", {})
    nmap = threat.get("nmap", {})

    vt_malicious = vt.get("malicious", 0) if isinstance(vt, dict) else 0
    abuse_score = abuse.get("abuse_confidence_score", 0) if isinstance(abuse, dict) else 0

    exposed_services = []
    if isinstance(nmap, dict):
        for p in nmap.get("open_ports", []):
            service = p.get("service")
            product = p.get("product")
            version = p.get("version")
            port = p.get("port")
            exposed_services.append(f"{port}/{service} {product} {version}".strip())

    business_impact = "Low"
    technical_impact = "Low"
    priority = "P4"

    if severity == "Critical":
        business_impact = "High"
        technical_impact = "Critical"
        priority = "P1"
    elif severity == "High":
        business_impact = "Medium"
        technical_impact = "High"
        priority = "P2"
    elif severity == "Medium":
        business_impact = "Medium"
        technical_impact = "Medium"
        priority = "P3"

    summary_parts = [
        f"The IOC {ioc} ({ioc_type}) has been assessed as {severity} risk with a score of {score}/100."
    ]

    if vt_malicious:
        summary_parts.append(f"VirusTotal reports {vt_malicious} malicious detection(s).")

    if abuse_score:
        summary_parts.append(f"AbuseIPDB confidence score is {abuse_score}.")

    if exposed_services:
        summary_parts.append(f"Exposed services detected: {', '.join(exposed_services[:5])}.")

    if classification.get("categories"):
        summary_parts.append(
            f"Threat categories include: {', '.join(classification.get('categories', [])[:5])}."
        )

    key_risks = []
    for surface in attack_surface:
        service = surface.get("service")
        risks = surface.get("risks", [])
        if risks:
            key_risks.append(f"{service}: {', '.join(risks[:3])}")

    return {
        "executive_summary": " ".join(summary_parts),
        "business_impact": business_impact,
        "technical_impact": technical_impact,
        "recommended_priority": priority,
        "key_risks": key_risks,
        "final_decision": (
            "Immediate investigation recommended"
            if priority in ["P1", "P2"]
            else "Monitor and review periodically"
        )
    }

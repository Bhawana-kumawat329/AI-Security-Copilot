def generate_ioc_story(response):

    story = []

    threat = response.get("threat_data", {})
    risk = response.get("risk", {})

    vt = threat.get("virustotal", {})
    abuse = threat.get("abuseipdb", {})
    geo = threat.get("geoip", {})
    nmap = threat.get("nmap", {})
    mitre = threat.get("mitre_attack", [])

    # VirusTotal
    if isinstance(vt, dict):
        malicious = vt.get("malicious", 0)

        if malicious > 0:
            story.append(
                f"VirusTotal detected this IOC as malicious using {malicious} security engines."
            )

    # AbuseIPDB
    if isinstance(abuse, dict):

        score = abuse.get("abuse_confidence_score", 0)

        if score > 0:
            story.append(
                f"AbuseIPDB reports an abuse confidence score of {score}."
            )

        reports = abuse.get("total_reports", 0)

        if reports:
            story.append(
                f"This IOC has been reported {reports} times."
            )

    # Geo
    if isinstance(geo, dict):

        country = geo.get("country")
        isp = geo.get("isp")

        if country and isp:
            story.append(
                f"The IP is hosted in {country} using ISP {isp}."
            )

    # Open Ports
    ports = nmap.get("open_ports", [])

    if ports:

        port_list = []

        for p in ports:
            port_list.append(str(p["port"]))

        story.append(
            f"Nmap detected open ports: {', '.join(port_list)}."
        )

        for p in ports:

            if p["service"] == "ssh":
                story.append(
                    "SSH exposure may allow brute-force or credential attacks."
                )

            if p["service"] in ["http", "https"]:
                story.append(
                    "Web service detected. Review for outdated software and web vulnerabilities."
                )

    # MITRE
    if mitre:

        techniques = len(mitre)

        story.append(
            f"{techniques} MITRE ATT&CK techniques were mapped during analysis."
        )

    # Final Verdict

    severity = risk.get("severity", "Unknown")

    if severity == "High":

        verdict = (
            "Overall assessment: HIGH RISK. Immediate investigation and containment are recommended."
        )

    elif severity == "Medium":

        verdict = (
            "Overall assessment: MEDIUM RISK. Continuous monitoring and patch verification are recommended."
        )

    else:

        verdict = (
            "Overall assessment: LOW RISK. Continue monitoring."
        )

    story.append(verdict)

    return {
        "story": story,
        "executive_summary": " ".join(story)
    }

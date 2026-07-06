def analyze_attack_surface(nmap_result):
    if not isinstance(nmap_result, dict):
        return []

    surfaces = []

    for p in nmap_result.get("open_ports", []):
        port = p.get("port")
        service = (p.get("service") or "").lower()
        product = p.get("product")
        version = p.get("version")

        item = {
            "port": port,
            "service": service,
            "product": product,
            "version": version,
            "risks": [],
            "recommendations": []
        }

        if port == 22 or service == "ssh":
            item["risks"] = ["Brute-force login", "Credential stuffing", "Unauthorized remote access"]
            item["recommendations"] = ["Restrict SSH to trusted IPs", "Disable password login", "Use key-based authentication"]

        elif port in [80, 443] or service in ["http", "https"]:
            item["risks"] = ["Web exploitation", "Information disclosure", "Outdated server vulnerabilities"]
            item["recommendations"] = ["Patch web server", "Review HTTP headers", "Monitor access logs"]

        elif port == 445:
            item["risks"] = ["Lateral movement", "Ransomware spread", "Unauthorized file access"]
            item["recommendations"] = ["Block SMB publicly", "Disable SMBv1", "Restrict to internal network"]

        elif port == 3389:
            item["risks"] = ["RDP brute-force", "Ransomware entry point"]
            item["recommendations"] = ["Restrict RDP to VPN", "Enable MFA", "Disable if unused"]

        else:
            item["risks"] = ["Exposed network service"]
            item["recommendations"] = ["Verify business need", "Restrict access if unnecessary"]

        surfaces.append(item)

    return surfaces

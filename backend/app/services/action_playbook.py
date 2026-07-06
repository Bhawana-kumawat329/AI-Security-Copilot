def generate_action_playbooks(investigation):
    threat_data = investigation.get("threat_data", {})
    abuse = threat_data.get("abuseipdb", {})
    nmap = threat_data.get("nmap", {})
    cves = threat_data.get("cves", [])

    playbooks = []

    # AbuseIPDB IP blocking playbook
    if isinstance(abuse, dict):
        ip = abuse.get("ip")
        abuse_score = abuse.get("abuse_confidence_score", 0)

        if ip and abuse_score >= 10:
            playbooks.append({
                "issue": "Suspicious IP Reputation",
                "risk": "This IP has abuse reports and may be involved in malicious activity.",
                "recommended_actions": [
                    "Monitor traffic from this IP.",
                    "Check firewall and server logs.",
                    "Block the IP if it is not business-critical."
                ],
                "linux_commands": [
                    f"sudo ufw deny from {ip}",
                    f"sudo iptables -A INPUT -s {ip} -j DROP"
                ]
            })

    # Nmap exposed services playbooks
    if isinstance(nmap, dict):
        for port_info in nmap.get("open_ports", []):
            port = port_info.get("port")
            service = port_info.get("service")
            product = port_info.get("product")
            version = port_info.get("version")

            if port == 22:
                playbooks.append({
                    "issue": "SSH Port 22 Exposed",
                    "risk": "Public SSH exposure may allow brute-force attacks or unauthorized access attempts.",
                    "recommended_actions": [
                        "Allow SSH only from trusted IP addresses.",
                        "Disable password-based SSH login.",
                        "Use SSH key-based authentication.",
                        "Review failed login attempts."
                    ],
                    "linux_commands": [
                        "sudo ufw allow from YOUR_TRUSTED_IP to any port 22",
                        "sudo nano /etc/ssh/sshd_config",
                        "Set: PasswordAuthentication no",
                        "sudo systemctl restart ssh",
                        "sudo grep 'Failed password' /var/log/auth.log"
                    ]
                })

            if port == 80 or port == 443:
                playbooks.append({
                    "issue": f"Web Service Exposed on Port {port}",
                    "risk": "Public web services can be targeted for scanning, exploitation, and misconfiguration attacks.",
                    "recommended_actions": [
                        "Verify web server version.",
                        "Check for outdated software.",
                        "Disable unnecessary modules.",
                        "Review HTTP security headers.",
                        "Monitor access logs for suspicious requests."
                    ],
                    "linux_commands": [
                        "curl -I http://TARGET_DOMAIN_OR_IP",
                        "apache2 -v || nginx -v",
                        "sudo tail -f /var/log/apache2/access.log",
                        "sudo tail -f /var/log/nginx/access.log"
                    ]
                })

            if port == 445:
                playbooks.append({
                    "issue": "SMB Port 445 Exposed",
                    "risk": "SMB exposure can lead to ransomware spread, lateral movement, and unauthorized file access.",
                    "recommended_actions": [
                        "Block SMB from the public internet.",
                        "Allow SMB only inside trusted internal networks.",
                        "Disable SMBv1.",
                        "Review file share permissions."
                    ],
                    "linux_commands": [
                        "sudo ufw deny 445",
                        "sudo iptables -A INPUT -p tcp --dport 445 -j DROP"
                    ]
                })

            if port == 3389:
                playbooks.append({
                    "issue": "RDP Port 3389 Exposed",
                    "risk": "Public RDP exposure is commonly abused for brute-force attacks and ransomware access.",
                    "recommended_actions": [
                        "Restrict RDP to VPN or trusted IPs.",
                        "Enable MFA.",
                        "Check Windows Event Logs for failed logins.",
                        "Disable RDP if not required."
                    ],
                    "linux_commands": [
                        "sudo ufw deny 3389"
                    ]
                })

            if product and version:
                playbooks.append({
                    "issue": f"Detected Service Version: {product} {version}",
                    "risk": "Exposed service versions may be mapped to known vulnerabilities.",
                    "recommended_actions": [
                        "Verify if this version is outdated.",
                        "Check vendor security advisories.",
                        "Patch to latest stable version if vulnerable."
                    ],
                    "linux_commands": [
                        "sudo apt update",
                        "sudo apt list --upgradable",
                        "sudo apt upgrade"
                    ]
                })

    # CVE based playbooks
    if isinstance(cves, list):
        for item in cves:
            product = item.get("product")
            version = item.get("version")

            for cve in item.get("cves", []):
                severity = str(cve.get("severity", "")).lower()
                cve_id = cve.get("cve_id")

                if severity in ["critical", "high"]:
                    playbooks.append({
                        "issue": f"{severity.title()} Vulnerability Detected: {cve_id}",
                        "risk": f"{product} {version} may be affected by a {severity} severity vulnerability.",
                        "recommended_actions": [
                            "Prioritize patching this vulnerability.",
                            "Apply vendor recommended mitigation.",
                            "Restrict public exposure until patched.",
                            "Monitor logs for exploitation attempts."
                        ],
                        "linux_commands": [
                            "sudo apt update",
                            "sudo apt upgrade",
                            "sudo systemctl restart apache2 || sudo systemctl restart nginx",
                            "sudo tail -f /var/log/apache2/access.log"
                        ]
                    })

    # Deduplicate by issue
    unique = []
    seen = set()

    for item in playbooks:
        issue = item.get("issue")
        if issue not in seen:
            unique.append(item)
            seen.add(issue)

    return unique

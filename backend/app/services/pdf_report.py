import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)


def generate_pdf_report(scan_result):
    scan_id = scan_result.get("scan_id", "latest")
    filename = f"security_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(REPORT_DIR, filename)

    doc = SimpleDocTemplate(filepath, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("AI Security Copilot - Investigation Report", styles["Title"]))
    story.append(Spacer(1, 12))

    risk = scan_result.get("risk", {})
    threat = scan_result.get("threat_data", {})
    summary = scan_result.get("soc_summary", {})

    basic_data = [
        ["IOC", scan_result.get("ioc")],
        ["IOC Type", scan_result.get("ioc_type")],
        ["Risk Score", f"{risk.get('score')}/100"],
        ["Severity", risk.get("severity")],
        ["Priority", summary.get("priority")]
    ]

    table = Table(basic_data)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(summary.get("summary", "No summary available."), styles["BodyText"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Key Observations", styles["Heading2"]))
    for obs in summary.get("key_observations", []):
        story.append(Paragraph(f"• {obs}", styles["BodyText"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Recommended Actions", styles["Heading2"]))
    for action in summary.get("recommended_actions", []):
        story.append(Paragraph(f"• {action}", styles["BodyText"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("VirusTotal", styles["Heading2"]))
    vt = threat.get("virustotal", {})
    if isinstance(vt, dict):
        story.append(Paragraph(
            f"Malicious: {vt.get('malicious')} | Suspicious: {vt.get('suspicious')} | Harmless: {vt.get('harmless')}",
            styles["BodyText"]
        ))

    story.append(Spacer(1, 12))
    story.append(Paragraph("AbuseIPDB", styles["Heading2"]))
    abuse = threat.get("abuseipdb", {})
    if isinstance(abuse, dict):
        story.append(Paragraph(
            f"Abuse Score: {abuse.get('abuse_confidence_score')} | Country: {abuse.get('country_code')} | ISP: {abuse.get('isp')}",
            styles["BodyText"]
        ))

    story.append(Spacer(1, 12))
    story.append(Paragraph("Open Ports", styles["Heading2"]))
    nmap = threat.get("nmap", {})
    if isinstance(nmap, dict):
        ports = nmap.get("open_ports", [])
        if ports:
            port_rows = [["Port", "Service", "Product", "Version"]]
            for p in ports:
                port_rows.append([
                    p.get("port"),
                    p.get("service"),
                    p.get("product"),
                    p.get("version")
                ])
            port_table = Table(port_rows)
            port_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(port_table)

    story.append(Spacer(1, 12))
    story.append(Paragraph("MITRE ATT&CK Mapping", styles["Heading2"]))
    for m in threat.get("mitre_attack", []):
        story.append(Paragraph(
            f"• {m.get('technique_id')} - {m.get('technique_name')} ({m.get('tactic')})",
            styles["BodyText"]
        ))

    story.append(Spacer(1, 12))
    story.append(Paragraph("Action Playbooks", styles["Heading2"]))
    for pb in summary.get("playbooks", []):
        story.append(Paragraph(f"<b>{pb.get('issue')}</b>", styles["BodyText"]))
        story.append(Paragraph(pb.get("risk", ""), styles["BodyText"]))
        for cmd in pb.get("linux_commands", [])[:4]:
            story.append(Paragraph(f"Command: {cmd}", styles["Code"]))

    doc.build(story)

    return {
        "filename": filename,
        "path": filepath
    }

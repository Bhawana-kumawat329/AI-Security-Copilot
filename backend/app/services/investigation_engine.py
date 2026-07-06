from concurrent.futures import ThreadPoolExecutor, as_completed
from app.services.validator import detect_ioc_type
from app.services.virustotal import analyze_with_virustotal
from app.services.abuseipdb import analyze_with_abuseipdb
from app.services.whois import get_whois_info
from app.services.geoip import get_geoip_info
from app.services.nmap_scan import run_nmap_scan
from app.services.cve_lookup import map_cves_from_nmap
from app.services.risk_engine import calculate_risk_score
from app.services.mitre_mapping import map_mitre_from_findings
from app.services.soc_summary import build_soc_summary
from app.services.history_service import save_scan_result
from app.services.pdf_report import generate_pdf_report
from app.services.correlation_engine import generate_ioc_story
from app.services.attack_surface import analyze_attack_surface
from app.services.threat_classification import classify_threat
from app.services.correlation_engine import generate_ioc_story
from app.services.executive_verdict import generate_executive_verdict
from app.services.dashboard_metrics import build_cve_summary, build_confidence_breakdown

def safe_run(function, *args):
    try:
        return function(*args)
    except Exception as e:
        return {"error": str(e)}


def investigate_ioc(ioc: str):
    ioc_result = detect_ioc_type(ioc)

    if not ioc_result["valid"]:
        return {
            "success": False,
            "message": "Invalid IOC",
            "ioc": ioc,
            "ioc_type": "UNKNOWN"
        }

    ioc_type = ioc_result["type"]

    results = {
        "virustotal": None,
        "abuseipdb": "Only available for IP addresses",
        "whois": "Only available for domains",
        "geoip": "Only available for IP addresses",
        "nmap": "Only available for IP and Domain"
    }

    tasks = {}

    with ThreadPoolExecutor(max_workers=5) as executor:
        tasks[executor.submit(safe_run, analyze_with_virustotal, ioc, ioc_type)] = "virustotal"

        if ioc_type == "IP":
            tasks[executor.submit(safe_run, analyze_with_abuseipdb, ioc)] = "abuseipdb"
            tasks[executor.submit(safe_run, get_geoip_info, ioc)] = "geoip"

        if ioc_type == "DOMAIN":
            tasks[executor.submit(safe_run, get_whois_info, ioc)] = "whois"

        if ioc_type in ["IP", "DOMAIN"]:
            tasks[executor.submit(safe_run, run_nmap_scan, ioc)] = "nmap"

        for task in as_completed(tasks):
            key = tasks[task]
            results[key] = task.result()

    cve_result = []
    if isinstance(results["nmap"], dict):
        cve_result = map_cves_from_nmap(results["nmap"])

    mitre_result = map_mitre_from_findings(results["nmap"], cve_result)
    attack_surface = analyze_attack_surface(results["nmap"])

    risk_result = calculate_risk_score(
        results["virustotal"],
        results["abuseipdb"],
        results["nmap"],
        cve_result,
        mitre_result
    )

    response = {
        "success": True,
        "ioc": ioc,
        "ioc_type": ioc_type,
        "risk": risk_result,
        "threat_data": {
            "virustotal": results["virustotal"],
            "abuseipdb": results["abuseipdb"],
            "whois": results["whois"],
            "geoip": results["geoip"],
            "nmap": results["nmap"],
            "cves": cve_result,
            "mitre_attack": mitre_result
        }
    }

    response["attack_surface"] = attack_surface
    response["threat_classification"] = classify_threat(response)
    response["ioc_story"] = generate_ioc_story(response)
    response["executive_verdict"] = generate_executive_verdict(response)
    response["cve_summary"] = build_cve_summary(cve_result)
    response["confidence_breakdown"] = build_confidence_breakdown(response)
    response["soc_summary"] = build_soc_summary(response)

    scan_id = save_scan_result(response)
    response["scan_id"] = scan_id

    report = generate_pdf_report(response)
    response["pdf_report"] = report

    return response

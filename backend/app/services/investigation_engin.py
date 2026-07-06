from app.services.validator import detect_ioc_type
from app.services.virustotal import analyze_with_virustotal
from app.services.abuseipdb import analyze_with_abuseipdb
from app.services.whois import get_whois_info
from app.services.geoip import get_geoip_info
from app.services.nmap_scan import run_nmap_scan
from app.services.cve_lookup import map_cves_from_nmap
from app.services.risk_engine import calculate_risk_score


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

    vt_result = analyze_with_virustotal(ioc, ioc_type)

    abuse_result = "Only available for IP addresses"
    if ioc_type == "IP":
        abuse_result = analyze_with_abuseipdb(ioc)

    whois_result = "Only available for domains"
    if ioc_type == "DOMAIN":
        whois_result = get_whois_info(ioc)

    geoip_result = "Only available for IP addresses"
    if ioc_type == "IP":
        geoip_result = get_geoip_info(ioc)

    nmap_result = "Only available for IP and Domain"
    if ioc_type in ["IP", "DOMAIN"]:
        nmap_result = run_nmap_scan(ioc)

    cve_result = []
    if isinstance(nmap_result, dict):
        cve_result = map_cves_from_nmap(nmap_result)

    risk_result = calculate_risk_score(vt_result, abuse_result)

    return {
        "success": True,
        "ioc": ioc,
        "ioc_type": ioc_type,
        "risk": risk_result,
        "threat_data": {
            "virustotal": vt_result,
            "abuseipdb": abuse_result,
            "whois": whois_result,
            "geoip": geoip_result,
            "nmap": nmap_result,
            "cves": cve_result
        }
    }

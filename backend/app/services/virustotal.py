import os
import base64
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def _headers():
    return {"x-apikey": VT_API_KEY}


def _url_id(url: str):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _extract_detection_details(attributes):
    stats = attributes.get("last_analysis_stats", {})
    results = attributes.get("last_analysis_results", {})

    malicious_engines = []
    suspicious_engines = []

    for engine, detail in results.items():
        category = detail.get("category")
        result = detail.get("result")

        item = {
            "engine": engine,
            "category": category,
            "result": result or "No label"
        }

        if category == "malicious":
            malicious_engines.append(item)
        elif category == "suspicious":
            suspicious_engines.append(item)

    total_engines = sum(stats.values()) if stats else 0
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    detection_rate = f"{malicious + suspicious}/{total_engines}" if total_engines else "0/0"

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "timeout": stats.get("timeout", 0),
        "detection_rate": detection_rate,
        "malicious_engines": malicious_engines[:10],
        "suspicious_engines": suspicious_engines[:10],
        "raw_stats": stats
    }


def analyze_with_virustotal(ioc: str, ioc_type: str):
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    try:
        if ioc_type == "IP":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"

        elif ioc_type == "DOMAIN":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"

        elif ioc_type == "URL":
            url = f"https://www.virustotal.com/api/v3/urls/{_url_id(ioc)}"

        elif ioc_type in ["MD5", "SHA1", "SHA256"]:
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"

        else:
            return {"error": "VirusTotal does not support this IOC type yet"}

        response = requests.get(url, headers=_headers(), timeout=20)

        if response.status_code != 200:
            return {
                "error": "VirusTotal request failed",
                "status_code": response.status_code
            }

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})

        vt_output = _extract_detection_details(attributes)

        vt_output["reputation"] = attributes.get("reputation")
        vt_output["last_analysis_date"] = attributes.get("last_analysis_date")
        vt_output["tags"] = attributes.get("tags", [])

        if ioc_type == "DOMAIN":
            vt_output["registrar"] = attributes.get("registrar")
            vt_output["creation_date"] = attributes.get("creation_date")
            vt_output["last_dns_records_date"] = attributes.get("last_dns_records_date")

        if ioc_type == "IP":
            vt_output["network"] = attributes.get("network")
            vt_output["asn"] = attributes.get("asn")
            vt_output["as_owner"] = attributes.get("as_owner")
            vt_output["country"] = attributes.get("country")

        return vt_output

    except Exception as e:
        return {"error": str(e)}

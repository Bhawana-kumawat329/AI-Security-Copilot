import requests
from app.services.version_engine import get_version_status

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

GENERIC_SERVICES = {
    "http", "https", "ssl", "tcpwrapped", "domain", "dns",
    "ftp", "smtp", "pop3", "imap", "unknown"
}

OS_CPE_KEYWORDS = ["linux_kernel", "linux"]


def get_severity_from_score(score):
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def extract_cvss(metrics):
    if not metrics:
        return None, "Unknown", None

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics:
            metric = metrics[key][0]
            cvss = metric.get("cvssData", {})
            score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity") or metric.get("baseSeverity") or get_severity_from_score(score)
            vector = cvss.get("vectorString")
            return score, severity, vector

    return None, "Unknown", None


def parse_cve_items(data):
    results = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})

        description = "No description available"
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", description)
                break

        cvss_score, severity, vector = extract_cvss(cve.get("metrics", {}))

        references = []
        for ref in cve.get("references", [])[:5]:
            if isinstance(ref, dict) and ref.get("url"):
                references.append(ref.get("url"))

        results.append({
            "cve_id": cve.get("id"),
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": vector,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": description[:600],
            "references": references,
            "exploit_available": any(
                "exploit" in (url or "").lower()
                for url in references
            )
        })

    return results


def search_cves_by_keyword(keyword, limit=5):
    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": limit,
            "noRejected": ""
        }

        response = requests.get(NVD_BASE_URL, params=params, timeout=20)

        if response.status_code != 200:
            return {
                "status": "unavailable",
                "message": "NVD keyword lookup failed",
                "status_code": response.status_code,
                "cves": []
            }

        return {
            "status": "success",
            "message": "CVE lookup completed",
            "cves": parse_cve_items(response.json())
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "cves": []
        }


def should_search(product, version, service):
    product_l = (product or "").strip().lower()
    service_l = (service or "").strip().lower()

    if not product_l:
        return False

    if product_l in GENERIC_SERVICES:
        return False

    if service_l in GENERIC_SERVICES and not version:
        return False

    return True


def build_patch_advisory(product, version):
    status = get_version_status(product, version)

    advisory = {
        "current_version": status.get("current_version"),
        "latest_secure": status.get("latest_secure"),
        "update_required": status.get("update_required"),
        "message": status.get("message"),
        "recommendation": status.get("recommendation")
    }

    if status.get("update_required") is True:
        advisory["priority"] = "Patch Required"
        advisory["linux_commands"] = [
            "sudo apt update",
            "sudo apt list --upgradable",
            "sudo apt upgrade"
        ]
    else:
        advisory["priority"] = "Monitor"
        advisory["linux_commands"] = []

    return advisory


def map_cves_from_nmap(nmap_result):
    if not isinstance(nmap_result, dict):
        return []

    final_results = []

    for port in nmap_result.get("open_ports", []):
        service = port.get("service") or ""
        product = port.get("product") or ""
        version = port.get("version") or ""
        cpe_list = port.get("cpe", [])

        if isinstance(cpe_list, str):
            cpe_list = [cpe_list] if cpe_list else []

        version_status = get_version_status(product or service, version)
        patch_advisory = build_patch_advisory(product or service, version)

        if not should_search(product, version, service):
            final_results.append({
                "port": port.get("port"),
                "service": service,
                "product": product or service,
                "version": version,
                "search_method": "skipped",
                "search_keyword": None,
                "version_status": version_status,
                "patch_advisory": patch_advisory,
                "lookup_status": "skipped",
                "lookup_message": "Generic service or missing product/version",
                "cves": []
            })
            continue

        # Avoid bad OS CPE lookup like cpe:/o:linux:linux_kernel for OpenSSH
        useful_cpes = [
            cpe for cpe in cpe_list
            if not any(os_key in cpe.lower() for os_key in OS_CPE_KEYWORDS)
        ]

        # NVD cpeName often fails for old URI-style CPE from nmap, so keyword lookup is more stable here
        keyword = f"{product} {version}".strip()
        lookup = search_cves_by_keyword(keyword, limit=5)

        cves = lookup.get("cves", [])

        final_results.append({
            "port": port.get("port"),
            "service": service,
            "product": product or service,
            "version": version,
            "search_method": "keyword",
            "search_keyword": keyword,
            "cpe_detected": cpe_list,
            "cpe_used": useful_cpes,
            "version_status": version_status,
            "patch_advisory": patch_advisory,
            "lookup_status": lookup.get("status"),
            "lookup_message": lookup.get("message"),
            "cves": cves,
            "cve_count": len(cves)
        })

    return final_results

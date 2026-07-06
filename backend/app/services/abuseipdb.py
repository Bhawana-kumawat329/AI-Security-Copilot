import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def analyze_with_abuseipdb(ip: str):
    if not ABUSEIPDB_API_KEY:
        return {"error": "AbuseIPDB API key not configured"}

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)

        if response.status_code != 200:
            return {
                "error": "AbuseIPDB request failed",
                "status_code": response.status_code
            }

        data = response.json().get("data", {})

        return {
            "ip": data.get("ipAddress"),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports")
        }

    except Exception as e:
        return {"error": str(e)}

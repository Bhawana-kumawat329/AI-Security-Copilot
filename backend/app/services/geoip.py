import requests

def get_geoip_info(ip: str):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=10)
        data = response.json()

        if data.get("status") != "success":
            return {"error": "GeoIP lookup failed"}

        return {
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "as": data.get("as"),
            "lat": data.get("lat"),
            "lon": data.get("lon")
        }

    except Exception as e:
        return {"error": str(e)}

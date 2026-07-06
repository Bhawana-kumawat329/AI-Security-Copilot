import re
import ipaddress
from urllib.parse import urlparse

def detect_ioc_type(value: str):
    value = value.strip()

    if not value:
        return {"valid": False, "type": "UNKNOWN", "message": "Empty input"}

    try:
        ipaddress.ip_address(value)
        return {"valid": True, "type": "IP", "value": value}
    except ValueError:
        pass

    if re.fullmatch(r"^[a-fA-F0-9]{32}$", value):
        return {"valid": True, "type": "MD5", "value": value}

    if re.fullmatch(r"^[a-fA-F0-9]{40}$", value):
        return {"valid": True, "type": "SHA1", "value": value}

    if re.fullmatch(r"^[a-fA-F0-9]{64}$", value):
        return {"valid": True, "type": "SHA256", "value": value}

    if re.fullmatch(r"^[\w\.-]+@[\w\.-]+\.\w+$", value):
        return {"valid": True, "type": "EMAIL", "value": value}

    parsed = urlparse(value)
    if parsed.scheme in ["http", "https"] and parsed.netloc:
        return {"valid": True, "type": "URL", "value": value}

    domain_regex = r"^(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,}$"
    if re.fullmatch(domain_regex, value):
        return {"valid": True, "type": "DOMAIN", "value": value}

    return {"valid": False, "type": "UNKNOWN", "value": value, "message": "Invalid IOC"}

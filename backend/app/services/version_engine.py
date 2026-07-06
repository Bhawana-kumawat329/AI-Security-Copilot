import re

LATEST_SECURE = {
    "apache": "2.4.68",
    "apache httpd": "2.4.68",
    "httpd": "2.4.68",
    "openssh": "10.0",
    "nginx": "1.27.5"
}

def normalize_version(version):
    nums = re.findall(r"\d+", version or "")
    nums = [int(x) for x in nums[:3]]
    while len(nums) < 3:
        nums.append(0)
    return nums

def get_version_status(product, version):
    product_l = (product or "").lower()
    latest = None

    for key, value in LATEST_SECURE.items():
        if key in product_l:
            latest = value
            break

    if not latest or not version:
        return {
            "current_version": version,
            "latest_secure": latest or "Unknown",
            "update_required": None,
            "message": "Version check unavailable"
        }

    current_v = normalize_version(version)
    latest_v = normalize_version(latest)
    outdated = current_v < latest_v

    return {
        "current_version": version,
        "latest_secure": latest,
        "update_required": outdated,
        "message": "Update Required" if outdated else "Up to Date",
        "recommendation": f"Upgrade {product} from {version} to {latest}" if outdated else "No upgrade required"
    }

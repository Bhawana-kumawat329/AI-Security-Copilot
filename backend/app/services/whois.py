import whois

def get_whois_info(domain: str):
    try:
        data = whois.whois(domain)

        return {
            "domain_name": str(data.domain_name),
            "registrar": str(data.registrar),
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "name_servers": data.name_servers,
            "emails": str(data.emails)
        }

    except Exception as e:
        return {"error": str(e)}

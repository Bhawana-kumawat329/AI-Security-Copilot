import socket
import nmap


def resolve_target(target: str):
    try:
        socket.inet_aton(target)
        return target
    except OSError:
        try:
            return socket.gethostbyname(target)
        except Exception:
            return None


def run_nmap_scan(target: str):
    ip = resolve_target(target)

    if not ip:
        return {
            "error": "Unable to resolve target",
            "target": target
        }

    try:
        scanner = nmap.PortScanner()

        scanner.scan(
            ip,
            arguments="-Pn -sV -sC --version-all --top-ports 100"
        )

        if ip not in scanner.all_hosts():
            return {
                "error": "Host not reachable or scan failed",
                "target": target,
                "resolved_ip": ip
            }

        ports = []

        for proto in scanner[ip].all_protocols():
            for port in scanner[ip][proto]:
                service = scanner[ip][proto][port]

                cpe_data = service.get("cpe", [])
                if isinstance(cpe_data, str):
                    cpe_data = [cpe_data] if cpe_data else []

                ports.append({
                    "port": port,
                    "protocol": proto,
                    "state": service.get("state", ""),
                    "service": service.get("name", ""),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "extrainfo": service.get("extrainfo", ""),
                    "cpe": cpe_data
                })

        return {
            "target": target,
            "resolved_ip": ip,
            "state": scanner[ip].state(),
            "open_ports": ports
        }

    except Exception as e:
        return {
            "error": str(e),
            "target": target,
            "resolved_ip": ip
        }

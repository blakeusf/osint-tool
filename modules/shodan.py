import requests, os

def check_ip(ip):
    key = os.getenv("SHODAN_API_KEY")
    url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
    r = requests.get(url)
    if r.status_code != 200:
        return {"error": f"Shodan returned {r.status_code}"}
    d = r.json()
    return {
        "open_ports": d.get("ports", []),
        "hostnames": d.get("hostnames", []),
        "org": d.get("org", "N/A"),
        "os": d.get("os", "Unknown"),
        "vulns": list(d.get("vulns", {}).keys()),
    }
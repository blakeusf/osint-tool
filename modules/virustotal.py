import requests, os

def check_ip(ip):
    key = os.getenv("VT_API_KEY")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": key}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return {"error": f"VT returned {r.status_code}"}
    data = r.json()["data"]["attributes"]
    return {
        "malicious": data["last_analysis_stats"]["malicious"],
        "suspicious": data["last_analysis_stats"]["suspicious"],
        "country": data.get("country", "N/A"),
        "owner": data.get("as_owner", "N/A"),
    }
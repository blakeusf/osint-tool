import requests, os

def check_ip(ip):
    key = os.getenv("ABUSE_API_KEY")
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get(url, headers=headers, params=params)
    if r.status_code != 200:
        return {"error": f"AbuseIPDB returned {r.status_code}"}
    d = r.json()["data"]
    return {
        "abuse_score": d["abuseConfidenceScore"],
        "total_reports": d["totalReports"],
        "last_reported": d.get("lastReportedAt", "Never"),
        "usage_type": d.get("usageType", "N/A"),
    }
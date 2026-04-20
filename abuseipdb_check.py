"""
AbuseIPDB IP Reputation Check
Used in Splunk SOAR playbooks for automated alert enrichment and threat triage.
Author: Akanksha Christeena | SecureWithAkanksha
"""

import requests

def check_abuseipdb(ip_address: str, api_key: str) -> dict:
    """
    Query AbuseIPDB for IP abuse confidence score.
    Returns abuse score and verdict for SOAR decision logic.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()["data"]

        return {
            "ip": ip_address,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "Unknown"),
            "total_reports": data.get("totalReports", 0),
            "verdict": "MALICIOUS" if data.get("abuseConfidenceScore", 0) > 50 else "CLEAN"
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e), "ip": ip_address}


if __name__ == "__main__":
    result = check_abuseipdb("8.8.8.8", api_key="YOUR_API_KEY_HERE")
    print(result)

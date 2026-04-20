"""
VirusTotal IP Reputation Lookup
Used in Splunk SOAR phishing triage playbooks for automated alert enrichment.
Author: Akanksha Christeena | SecureWithAkanksha
"""

import requests

def check_ip_reputation(ip_address: str, api_key: str) -> dict:
    """
    Query VirusTotal for IP reputation data.
    Returns malicious vote count and verdict.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        
        return {
            "ip": ip_address,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "verdict": "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN"
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e), "ip": ip_address}


if __name__ == "__main__":
    result = check_ip_reputation("8.8.8.8", api_key="YOUR_API_KEY_HERE")
    print(result)

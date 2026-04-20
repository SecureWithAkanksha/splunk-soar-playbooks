"""
ServiceNow Incident Ticket Creator
Used in Splunk SOAR playbooks to auto-create incidents from enriched alerts.
Author: Akanksha Christeena | SecureWithAkanksha
"""

import requests
from requests.auth import HTTPBasicAuth

def create_incident(instance_url: str, username: str, password: str, 
                    alert_data: dict) -> dict:
    """
    Create a ServiceNow incident ticket from SOAR alert data.
    Returns ticket number and sys_id for tracking.
    """
    url = f"{instance_url}/api/now/table/incident"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    payload = {
        "short_description": alert_data.get("title", "Security Alert"),
        "description": alert_data.get("description", ""),
        "urgency": alert_data.get("urgency", "2"),
        "impact": alert_data.get("impact", "2"),
        "category": "Security",
        "assignment_group": "SOC Team"
    }

    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            auth=HTTPBasicAuth(username, password),
            timeout=10
        )
        response.raise_for_status()
        result = response.json().get("result", {})

        return {
            "ticket_number": result.get("number"),
            "sys_id": result.get("sys_id"),
            "status": "CREATED"
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e), "status": "FAILED"}


if __name__ == "__main__":
    alert = {
        "title": "Phishing Email Detected",
        "description": "Malicious IP flagged by VirusTotal and AbuseIPDB",
        "urgency": "1",
        "impact": "1"
    }
    result = create_incident(
        "https://your-instance.service-now.com",
        "admin", "password", alert
    )
    print(result)

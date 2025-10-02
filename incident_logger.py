from datetime import datetime
from typing import List, Dict

INCIDENTS: List[Dict] = []

def log_incident(ip: str, payload: str, rule: str):
    INCIDENTS.append({
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "payload": payload,
        "rule_triggered": rule,
        "status": "open"
    })
    print(f"🚨 Incident logged: {rule} from {ip}")

def get_incidents():
    return INCIDENTS

def mark_incident_handled(index: int):
    if 0 <= index < len(INCIDENTS):
        INCIDENTS[index]["status"] = "handled"
        print(f"✅ Incident {index} marked as handled")
        return True
    return False

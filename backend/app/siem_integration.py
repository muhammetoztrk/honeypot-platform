"""SIEM Integration Engine - Send events to SIEM systems"""
from sqlalchemy.orm import Session
from datetime import datetime
from . import models
import requests
import json


def send_to_siem(event: models.Event, siem: models.SIEMIntegration, db: Session):
    """Send event to SIEM system"""
    if not siem.enabled:
        return {"status": "skipped", "reason": "Integration disabled"}
    
    try:
        event_data = {
            "timestamp": event.ts.isoformat(),
            "source_ip": event.src_ip,
            "event_type": event.event_type,
            "honeypot_id": event.honeypot_id,
            "payload": event.payload,
            "session_id": event.session_id,
        }
        
        headers = {"Content-Type": "application/json"}
        if siem.api_key:
            headers["Authorization"] = f"Bearer {siem.api_key}"
        
        if siem.siem_type == "splunk":
            # Splunk HEC (HTTP Event Collector)
            url = f"{siem.endpoint}/services/collector/event"
            payload = {
                "event": event_data,
                "sourcetype": "honeypot",
                "source": "honeypot-platform",
            }
            response = requests.post(url, json=payload, headers=headers, timeout=5)
        
        elif siem.siem_type == "qradar":
            # QRadar LEEF format
            url = f"{siem.endpoint}/api/events"
            leef = f"LEEF:1.0|Honeypot|Platform|1.0|{event.event_type}|src={event.src_ip}"
            payload = {"leef": leef, "data": event_data}
            response = requests.post(url, json=payload, headers=headers, timeout=5)
        
        elif siem.siem_type == "zabbix":
            # Zabbix API
            url = f"{siem.endpoint}/api_jsonrpc.php"
            payload = {
                "jsonrpc": "2.0",
                "method": "event.create",
                "params": {
                    "name": f"Honeypot Event: {event.event_type}",
                    "description": json.dumps(event_data),
                    "severity": 3,  # Average
                },
                "id": 1,
            }
            if siem.api_key:
                payload["auth"] = siem.api_key
            response = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=5)
        
        elif siem.siem_type == "logsign":
            # Logsign API
            url = f"{siem.endpoint}/api/v1/events"
            payload = {
                "event": event_data,
                "source": "honeypot-platform",
                "category": "security",
            }
            response = requests.post(url, json=payload, headers=headers, timeout=5)
        
        elif siem.siem_type == "elasticsearch":
            # Elasticsearch
            url = f"{siem.endpoint}/honeypot-events/_doc"
            response = requests.post(url, json=event_data, headers=headers, timeout=5)
        
        elif siem.siem_type == "graylog":
            # Graylog GELF format
            url = f"{siem.endpoint}/gelf"
            gelf_data = {
                "version": "1.1",
                "host": "honeypot-platform",
                "short_message": f"{event.event_type} from {event.src_ip}",
                "level": 6,  # Info
                "_event_type": event.event_type,
                "_source_ip": event.src_ip,
                "_honeypot_id": event.honeypot_id,
            }
            response = requests.post(url, json=gelf_data, headers=headers, timeout=5)
        
        elif siem.siem_type == "wazuh":
            # Wazuh API
            url = f"{siem.endpoint}/events"
            payload = {
                "agent": {
                    "id": "honeypot-platform",
                    "name": "honeypot-platform",
                },
                "manager": {
                    "name": "honeypot-platform",
                },
                "data": event_data,
            }
            response = requests.post(url, json=payload, headers=headers, timeout=5)
        
        else:
            # Generic HTTP/HTTPS
            response = requests.post(siem.endpoint, json=event_data, headers=headers, timeout=5)
        
        return {
            "status": "success" if response.status_code in [200, 201, 202] else "error",
            "status_code": response.status_code,
            "siem": siem.name,
        }
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "siem": siem.name,
        }


def send_event_to_all_siems(event: models.Event, db: Session):
    """Send event to all enabled SIEM integrations"""
    siems = db.query(models.SIEMIntegration).filter_by(enabled=True).all()
    results = []
    
    for siem in siems:
        result = send_to_siem(event, siem, db)
        results.append(result)
    
    return results


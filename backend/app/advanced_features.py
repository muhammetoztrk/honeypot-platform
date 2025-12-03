"""Advanced Features - Additional capabilities"""
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from . import models
import json


def generate_attack_timeline(ip: str, db: Session, hours: int = 24) -> dict:
    """Generate detailed attack timeline for an IP"""
    start_time = datetime.utcnow() - timedelta(hours=hours)
    events = db.query(models.Event).filter(
        models.Event.src_ip == ip,
        models.Event.ts >= start_time
    ).order_by(models.Event.ts.asc()).all()
    
    timeline = []
    for event in events:
        timeline.append({
            "timestamp": event.ts.isoformat(),
            "event_type": event.event_type,
            "honeypot_id": event.honeypot_id,
            "payload": event.payload,
        })
    
    return {
        "ip": ip,
        "total_events": len(events),
        "time_range_hours": hours,
        "timeline": timeline,
    }


def calculate_attack_complexity(ip: str, db: Session) -> dict:
    """Calculate attack complexity score"""
    events = db.query(models.Event).filter_by(src_ip=ip).all()
    
    if not events:
        return {"complexity": "low", "score": 0}
    
    # Factors
    unique_honeypots = len(set(e.honeypot_id for e in events))
    unique_event_types = len(set(e.event_type for e in events))
    time_span = (events[-1].ts - events[0].ts).total_seconds() / 3600
    
    score = 0
    score += min(unique_honeypots * 10, 30)
    score += min(unique_event_types * 15, 30)
    score += min(time_span / 24 * 20, 20)  # Longer = more complex
    score += min(len(events) / 10, 20)
    
    if score < 30:
        complexity = "low"
    elif score < 60:
        complexity = "medium"
    else:
        complexity = "high"
    
    return {
        "complexity": complexity,
        "score": int(score),
        "factors": {
            "unique_honeypots": unique_honeypots,
            "unique_event_types": unique_event_types,
            "time_span_hours": time_span,
            "total_events": len(events),
        },
    }


def detect_data_exfiltration(ip: str, db: Session) -> dict:
    """Detect potential data exfiltration attempts"""
    events = db.query(models.Event).filter_by(src_ip=ip).all()
    
    exfiltration_indicators = []
    
    for event in events:
        payload = event.payload or {}
        
        # Check for file downloads
        if payload.get("path") and any(keyword in payload["path"].lower() for keyword in [".git", ".env", "backup", "dump", "export"]):
            exfiltration_indicators.append({
                "type": "sensitive_file_access",
                "path": payload["path"],
                "timestamp": event.ts.isoformat(),
            })
        
        # Check for database queries that might extract data
        if event.event_type == "db_query":
            query = payload.get("query", "").lower()
            if any(keyword in query for keyword in ["select *", "dump", "export", "backup"]):
                exfiltration_indicators.append({
                    "type": "data_extraction_query",
                    "query": payload["query"],
                    "timestamp": event.ts.isoformat(),
                })
        
        # Check for large data transfers
        if payload.get("bytes_transferred", 0) > 1000000:  # 1MB
            exfiltration_indicators.append({
                "type": "large_transfer",
                "bytes": payload["bytes_transferred"],
                "timestamp": event.ts.isoformat(),
            })
    
    return {
        "detected": len(exfiltration_indicators) > 0,
        "indicators": exfiltration_indicators,
        "severity": "high" if len(exfiltration_indicators) >= 3 else "medium" if len(exfiltration_indicators) >= 1 else "low",
    }


def generate_threat_hunting_query(ip: str, db: Session) -> dict:
    """Generate threat hunting queries for an IP"""
    events = db.query(models.Event).filter_by(src_ip=ip).all()
    
    queries = {
        "splunk": [],
        "elasticsearch": [],
        "generic": [],
    }
    
    if events:
        # Splunk query
        splunk_query = f'index=security src_ip="{ip}" | stats count by event_type'
        queries["splunk"].append(splunk_query)
        
        # Elasticsearch query
        es_query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": ip}},
                    ]
                }
            },
            "aggs": {
                "event_types": {
                    "terms": {"field": "event_type"}
                }
            }
        }
        queries["elasticsearch"].append(json.dumps(es_query, indent=2))
        
        # Generic SQL-like query
        generic_query = f"SELECT event_type, COUNT(*) FROM events WHERE src_ip = '{ip}' GROUP BY event_type"
        queries["generic"].append(generic_query)
    
    return queries


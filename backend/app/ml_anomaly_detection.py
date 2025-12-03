"""Machine Learning Anomaly Detection"""
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from collections import Counter
from . import models


def detect_ml_anomaly(ip: str, db: Session) -> dict:
    """Simple ML-based anomaly detection using statistical methods"""
    # Get events from last 24 hours
    start_time = datetime.utcnow() - timedelta(hours=24)
    events = db.query(models.Event).filter(
        models.Event.src_ip == ip,
        models.Event.ts >= start_time
    ).all()
    
    if len(events) < 5:
        return {"anomaly": False, "score": 0.0}
    
    # Feature extraction
    features = {
        "event_count": len(events),
        "unique_honeypots": len(set(e.honeypot_id for e in events)),
        "unique_event_types": len(set(e.event_type for e in events)),
        "time_span_hours": (events[-1].ts - events[0].ts).total_seconds() / 3600,
        "avg_events_per_hour": len(events) / max((events[-1].ts - events[0].ts).total_seconds() / 3600, 1),
    }
    
    # Simple anomaly scoring (can be replaced with actual ML model)
    anomaly_score = 0.0
    
    # High event count anomaly
    if features["event_count"] > 100:
        anomaly_score += 0.3
    
    # Rapid scanning anomaly
    if features["time_span_hours"] < 1 and features["event_count"] > 20:
        anomaly_score += 0.4
    
    # Diverse attack techniques
    if features["unique_event_types"] >= 5:
        anomaly_score += 0.2
    
    # Multiple honeypots touched
    if features["unique_honeypots"] >= 5:
        anomaly_score += 0.1
    
    return {
        "anomaly": anomaly_score > 0.5,
        "score": min(anomaly_score, 1.0),
        "features": features,
    }


def detect_attack_chain(ip: str, db: Session) -> dict:
    """Detect multi-stage attack chains"""
    start_time = datetime.utcnow() - timedelta(hours=24)
    events = db.query(models.Event).filter(
        models.Event.src_ip == ip,
        models.Event.ts >= start_time
    ).order_by(models.Event.ts.asc()).all()
    
    if len(events) < 3:
        return {"chain_detected": False}
    
    # Define attack stages
    stages = {
        "reconnaissance": ["web_request", "port_scan"],
        "initial_access": ["ssh_connection", "login_attempt"],
        "execution": ["ssh_command", "web_request"],
        "persistence": ["ssh_command"],
        "lateral_movement": ["ssh_connection"],
        "data_exfiltration": ["web_request", "file_download"],
    }
    
    detected_stages = []
    for stage_name, event_types in stages.items():
        if any(e.event_type in event_types for e in events):
            detected_stages.append(stage_name)
    
    if len(detected_stages) >= 3:
        return {
            "chain_detected": True,
            "stages": detected_stages,
            "total_events": len(events),
            "severity": "high" if len(detected_stages) >= 5 else "medium",
        }
    
    return {"chain_detected": False}


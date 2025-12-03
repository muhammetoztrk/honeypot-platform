"""Automated Response Actions"""
from sqlalchemy.orm import Session
from datetime import datetime
from . import models


def auto_block_ip(ip: str, reason: str, db: Session):
    """Automatically block an IP address"""
    existing = db.query(models.BlockedIP).filter_by(ip=ip).first()
    if existing:
        return existing
    
    blocked = models.BlockedIP(
        ip=ip,
        reason=f"Auto-blocked: {reason}",
        blocked_at=datetime.utcnow(),
    )
    db.add(blocked)
    db.commit()
    return blocked


def auto_create_incident(title: str, description: str, severity: str, event_ids: list, db: Session, user_id: int):
    """Automatically create an incident"""
    incident = models.Incident(
        title=title,
        description=description,
        severity=severity,
        status="open",
        created_by=user_id,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    
    # Link events
    for event_id in event_ids:
        link = models.IncidentEvent(incident_id=incident.id, event_id=event_id)
        db.add(link)
    
    db.commit()
    return incident


def auto_notify_soc(message: str, severity: str, db: Session):
    """Automatically notify SOC (via alert)"""
    alert = models.Alert(
        severity=severity,
        title="SOC Notification",
        message=message,
        created_at=datetime.utcnow(),
    )
    db.add(alert)
    db.commit()
    return alert


def execute_auto_response(trigger_type: str, ip: str, details: dict, db: Session, user_id: int = None):
    """Execute automated response based on trigger"""
    responses = []
    
    if trigger_type == "brute_force":
        if details.get("attempts", 0) >= 10:
            responses.append(auto_block_ip(ip, "Brute force attack detected", db))
            responses.append(auto_create_incident(
                f"Brute Force Attack from {ip}",
                f"Detected {details.get('attempts')} failed login attempts",
                "high",
                details.get("event_ids", []),
                db,
                user_id or 1,
            ))
    
    elif trigger_type == "port_scan":
        if details.get("ports_scanned", 0) >= 5:
            responses.append(auto_block_ip(ip, "Port scanning detected", db))
            responses.append(auto_notify_soc(f"Port scan detected from {ip}", "medium", db))
    
    elif trigger_type == "attack_chain":
        responses.append(auto_create_incident(
            f"Multi-Stage Attack from {ip}",
            f"Detected attack chain with {len(details.get('stages', []))} stages",
            "critical",
            details.get("event_ids", []),
            db,
            user_id or 1,
        ))
        responses.append(auto_block_ip(ip, "Multi-stage attack detected", db))
    
    return responses


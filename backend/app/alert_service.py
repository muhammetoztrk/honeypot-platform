from sqlalchemy.orm import Session
from datetime import datetime
from . import models


def check_and_create_alerts(event: models.Event, db: Session):
    """Check event for high-risk indicators and create alerts"""
    # Check if alert should be suppressed
    from .attacker_intelligence import should_suppress_alert
    if should_suppress_alert(event, db):
        return
    
    payload = event.payload or {}
    risk_score = 0

    # Calculate risk score based on event type and payload
    if event.event_type == "ssh_connection":
        commands = payload.get("commands", [])
        if len(commands) > 5:
            risk_score += 30
        if any("passwd" in cmd.lower() or "sudo" in cmd.lower() for cmd in commands):
            risk_score += 40
        if any("rm -rf" in cmd or "dd if=" in cmd for cmd in commands):
            risk_score += 50

    elif event.event_type == "web_request":
        if payload.get("method") == "POST" and payload.get("payload"):
            risk_score += 30
        if "/admin" in payload.get("path", "") or "/wp-admin" in payload.get("path", ""):
            risk_score += 40
    
    elif event.event_type in ["secrets_hunt", "sso_login_attempt", "router_access"]:
        risk_score += 50  # High-risk event types

    # Check IOC scores
    iocs = db.query(models.IOC).filter_by(ioc_type="ip", value=event.src_ip).all()
    for ioc in iocs:
        risk_score += min(ioc.score, 30)

    # Create alert if risk is high
    if risk_score >= 50:
        # Use aggregation to reduce noise
        from .attacker_intelligence import aggregate_alert
        aggregate_alert(event, db)


def check_ioc_alerts(ioc: models.IOC, db: Session):
    """Check IOC for high-risk indicators and create alerts"""
    if ioc.score >= 70 or ioc.seen_count >= 5:
        severity = "critical" if ioc.score >= 80 else "high"
        title = f"High-risk IOC detected: {ioc.ioc_type} - {ioc.value[:50]}"
        message = f"IOC type: {ioc.ioc_type}, Score: {ioc.score}, Seen: {ioc.seen_count}x"

        alert = models.Alert(
            severity=severity,
            title=title,
            message=message,
            ioc_id=ioc.id,
            created_at=datetime.utcnow(),
        )
        db.add(alert)

        # Send email notification
        from .email_service import send_alert_email
        send_alert_email(alert, db)


def create_alert(severity: str, title: str, message: str, event_id: int = None, ioc_id: int = None, db: Session = None):
    """Create an alert"""
    alert = models.Alert(
        severity=severity,
        title=title,
        message=message,
        event_id=event_id,
        ioc_id=ioc_id,
        created_at=datetime.utcnow(),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


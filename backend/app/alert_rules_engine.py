"""Alert Rules Engine - Evaluates rules and triggers actions"""
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from . import models
from .alert_service import create_alert
from .email_service import send_alert_email
import requests


def evaluate_alert_rules(event: Optional[models.Event] = None, ioc: Optional[models.IOC] = None, db: Session = None):
    """Evaluate all enabled alert rules and trigger actions"""
    if not db:
        return
    
    rules = db.query(models.AlertRule).filter_by(enabled=True).all()
    
    for rule in rules:
        if _rule_matches(rule, event, ioc):
            _execute_rule_actions(rule, event, ioc, db)


def _rule_matches(rule: models.AlertRule, event: Optional[models.Event], ioc: Optional[models.IOC]) -> bool:
    """Check if rule conditions match"""
    conditions = rule.conditions or {}
    
    # IOC-based rules
    if ioc:
        if conditions.get('min_score') and ioc.score < conditions['min_score']:
            return False
        if conditions.get('min_seen_count') and ioc.seen_count < conditions['min_seen_count']:
            return False
        if conditions.get('ioc_type') and ioc.ioc_type != conditions['ioc_type']:
            return False
        return True
    
    # Event-based rules
    if event:
        if conditions.get('event_type') and event.event_type != conditions['event_type']:
            return False
        if conditions.get('min_score') and event.payload.get('score', 0) < conditions['min_score']:
            return False
        return True
    
    return False


def _execute_rule_actions(rule: models.AlertRule, event: Optional[models.Event], ioc: Optional[models.IOC], db: Session):
    """Execute actions defined in the rule"""
    actions = rule.actions or {}
    
    # Create alert
    if event:
        create_alert(
            severity=actions.get('severity', 'high'),
            title=f"Rule Triggered: {rule.name}",
            message=f"Event {event.id} matched rule conditions",
            event_id=event.id,
            db=db
        )
    elif ioc:
        create_alert(
            severity=actions.get('severity', 'high'),
            title=f"Rule Triggered: {rule.name}",
            message=f"IOC {ioc.id} ({ioc.value}) matched rule conditions",
            ioc_id=ioc.id,
            db=db
        )
    
    # Block IP
    if actions.get('block_ip'):
        ip = None
        reason = f"Auto-blocked by rule: {rule.name}"
        
        if event:
            ip = event.src_ip
        elif ioc and ioc.ioc_type == 'ip':
            ip = ioc.value
        
        if ip:
            # Import here to avoid circular dependency
            from sqlalchemy.orm import Session
            existing = db.query(models.BlockedIP).filter_by(ip=ip).first()
            if not existing:
                blocked = models.BlockedIP(ip=ip, reason=reason, blocked_by=None)
                db.add(blocked)
                db.commit()
    
    # Send email
    if actions.get('send_email'):
        alert_email = actions.get('alert_email', '')
        if alert_email:
            try:
                send_alert_email(
                    to_email=alert_email,
                    subject=f"Alert Rule Triggered: {rule.name}",
                    message=f"Rule '{rule.name}' was triggered. Check the dashboard for details."
                )
            except Exception:
                pass  # Silently fail
    
    # Trigger webhook
    if actions.get('webhook_url'):
        webhook_url = actions['webhook_url']
        payload = {
            "rule_name": rule.name,
            "event_id": event.id if event else None,
            "ioc_id": ioc.id if ioc else None,
            "timestamp": str(event.ts if event else ioc.last_seen if ioc else ''),
        }
        try:
            requests.post(webhook_url, json=payload, timeout=5)
        except Exception:
            pass  # Silently fail


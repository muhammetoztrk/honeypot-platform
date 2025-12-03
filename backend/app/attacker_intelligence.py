"""Attacker Intelligence Engine - Risk Scoring and Profiling"""
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from . import models
import hashlib


def calculate_attacker_risk_score(ip: str, db: Session) -> int:
    """Calculate risk score (0-100) for an attacker IP"""
    # Get all events from this IP
    events = db.query(models.Event).filter_by(src_ip=ip).all()
    if not events:
        return 0
    
    score = 0
    
    # Base score from event count
    event_count = len(events)
    score += min(event_count * 2, 30)  # Max 30 points
    
    # Score from different honeypots touched
    honeypot_ids = set(e.honeypot_id for e in events)
    score += min(len(honeypot_ids) * 5, 20)  # Max 20 points
    
    # Score from event types (more dangerous = higher score)
    event_types = {}
    for e in events:
        event_types[e.event_type] = event_types.get(e.event_type, 0) + 1
    
    dangerous_types = {
        "secrets_hunt": 15,
        "sso_login_attempt": 12,
        "router_access": 10,
        "ssh_command": 8,
        "web_request": 5,
        "smtp_connection": 6,
    }
    
    for event_type, count in event_types.items():
        base_score = dangerous_types.get(event_type, 3)
        score += min(base_score * count, 20)  # Max 20 points per type
    
    # Score from MITRE techniques
    from .mitre_mapper import map_event_to_mitre
    mitre_techniques = set()
    for e in events:
        mappings = map_event_to_mitre(e, db)
        for m in mappings:
            mitre_techniques.add(m["technique_id"])
    
    score += min(len(mitre_techniques) * 5, 15)  # Max 15 points
    
    # Score from IOCs
    iocs = db.query(models.IOC).filter_by(ioc_type="ip", value=ip).all()
    if iocs:
        max_ioc_score = max(ioc.score for ioc in iocs)
        score += min(max_ioc_score // 2, 15)  # Max 15 points
    
    return min(score, 100)  # Cap at 100


def update_attacker_profile(ip: str, event: models.Event, db: Session):
    """Update or create attacker profile"""
    profile = db.query(models.AttackerProfile).filter_by(ip=ip).first()
    
    if not profile:
        profile = models.AttackerProfile(
            ip=ip,
            first_seen=event.ts,
            last_seen=event.ts,
            total_events=1,
            honeypots_touched=1,
        )
        db.add(profile)
    else:
        profile.last_seen = max(profile.last_seen, event.ts)
        profile.total_events += 1
        if event.honeypot_id not in profile.profile_data.get("honeypot_ids", []):
            profile.honeypots_touched += 1
            if "honeypot_ids" not in profile.profile_data:
                profile.profile_data["honeypot_ids"] = []
            profile.profile_data["honeypot_ids"].append(event.honeypot_id)
    
    # Recalculate risk score
    profile.risk_score = calculate_attacker_risk_score(ip, db)
    
    # Update MITRE techniques
    from .mitre_mapper import map_event_to_mitre
    mappings = map_event_to_mitre(event, db)
    existing_techniques = set(profile.mitre_techniques or [])
    for m in mappings:
        existing_techniques.add(m["technique_id"])
    profile.mitre_techniques = list(existing_techniques)
    
    db.commit()
    return profile


def get_top_attackers(db: Session, limit: int = 10, days: int = 30):
    """Get top attackers by risk score"""
    from datetime import datetime, timedelta
    start_date = datetime.utcnow() - timedelta(days=days)
    
    profiles = (
        db.query(models.AttackerProfile)
        .filter(models.AttackerProfile.last_seen >= start_date)
        .order_by(models.AttackerProfile.risk_score.desc())
        .limit(limit)
        .all()
    )
    
    return [
        {
            "ip": p.ip,
            "risk_score": p.risk_score,
            "total_events": p.total_events,
            "honeypots_touched": p.honeypots_touched,
            "mitre_techniques": len(p.mitre_techniques or []),
            "first_seen": p.first_seen.isoformat(),
            "last_seen": p.last_seen.isoformat(),
        }
        for p in profiles
    ]


def aggregate_alert(event: models.Event, db: Session) -> models.Alert:
    """Aggregate similar alerts to reduce noise"""
    # Create pattern hash: IP + event_type + path (if web)
    path = event.payload.get("path", "") if event.event_type.startswith("web") else ""
    pattern_str = f"{event.src_ip}:{event.event_type}:{path}"
    pattern_hash = hashlib.md5(pattern_str.encode()).hexdigest()
    
    # Check if aggregation exists
    aggregation = db.query(models.AlertAggregation).filter_by(pattern_hash=pattern_hash).first()
    
    if aggregation:
        # Update existing aggregation
        aggregation.count += 1
        aggregation.last_seen = event.ts
        db.commit()
        
        # Return existing alert if count is low, otherwise create new
        if aggregation.alert_id:
            existing_alert = db.query(models.Alert).filter_by(id=aggregation.alert_id).first()
            if existing_alert:
                # Update alert message with count
                existing_alert.message = f"Repeated {aggregation.count}x: {existing_alert.message.split(':')[-1]}"
                db.commit()
                return existing_alert
    
    # Create new aggregation
    aggregation = models.AlertAggregation(
        pattern_hash=pattern_hash,
        ip=event.src_ip,
        event_type=event.event_type,
        count=1,
        first_seen=event.ts,
        last_seen=event.ts,
    )
    db.add(aggregation)
    db.commit()
    db.refresh(aggregation)
    
    # Create alert
    severity = "high" if aggregation.count > 5 else "medium"
    alert = models.Alert(
        severity=severity,
        title=f"{event.event_type} from {event.src_ip}",
        message=f"Event detected: {event.event_type}" + (f" (repeated {aggregation.count}x)" if aggregation.count > 1 else ""),
        event_id=event.id,
        created_at=datetime.utcnow(),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    
    # Link alert to aggregation
    aggregation.alert_id = alert.id
    db.commit()
    
    return alert


def should_suppress_alert(event: models.Event, db: Session) -> bool:
    """Check if alert should be suppressed based on rules"""
    suppress_rules = db.query(models.SuppressRule).filter_by(enabled=True).all()
    
    for rule in suppress_rules:
        conditions = rule.conditions or {}
        
        # Check IP match
        if conditions.get("ip") and event.src_ip != conditions["ip"]:
            continue
        
        # Check event type match
        if conditions.get("event_type") and event.event_type != conditions["event_type"]:
            continue
        
        # Check duration (if rule has duration, check if it's still valid)
        duration_hours = conditions.get("duration_hours", 24)
        rule_age = (datetime.utcnow() - rule.created_at).total_seconds() / 3600
        if rule_age > duration_hours:
            continue  # Rule expired
        
        return True  # Should suppress
    
    return False


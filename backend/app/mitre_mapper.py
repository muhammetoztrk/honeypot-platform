"""MITRE ATT&CK Mapping Engine"""
from sqlalchemy.orm import Session
from . import models


def map_event_to_mitre(event: models.Event, db: Session) -> list:
    """Map an event to MITRE ATT&CK techniques"""
    mappings = db.query(models.MITREMapping).filter_by(event_type=event.event_type).all()
    return [{
        "technique_id": m.technique_id,
        "technique_name": m.technique_name,
        "tactic": m.tactic,
    } for m in mappings]


def get_mitre_statistics(db: Session, days: int = 30):
    """Get MITRE ATT&CK statistics"""
    from datetime import datetime, timedelta
    start_date = datetime.utcnow() - timedelta(days=days)
    events = db.query(models.Event).filter(models.Event.ts >= start_date).all()
    
    technique_counts = {}
    tactic_counts = {}
    
    for event in events:
        mappings = map_event_to_mitre(event, db)
        for m in mappings:
            technique_counts[m["technique_id"]] = technique_counts.get(m["technique_id"], 0) + 1
            tactic_counts[m["tactic"]] = tactic_counts.get(m["tactic"], 0) + 1
    
    return {
        "techniques": technique_counts,
        "tactics": tactic_counts,
        "total_events": len(events),
    }


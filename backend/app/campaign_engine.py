"""Campaign Engine - Deception Campaign Management"""
from sqlalchemy.orm import Session
from datetime import datetime
from . import models


def get_campaign_statistics(campaign_id: int, db: Session) -> dict:
    """Get statistics for a campaign"""
    campaign = db.query(models.Campaign).filter_by(id=campaign_id).first()
    if not campaign:
        return {}
    
    # Get campaign honeypots
    campaign_honeypots = db.query(models.CampaignHoneypot).filter_by(campaign_id=campaign_id).all()
    honeypot_ids = [ch.honeypot_id for ch in campaign_honeypots]
    
    # Get events from campaign honeypots
    events = db.query(models.Event).filter(models.Event.honeypot_id.in_(honeypot_ids)).all()
    
    # Get IOCs from campaign events
    event_ids = [e.id for e in events]
    campaign_events = db.query(models.CampaignEvent).filter(models.CampaignEvent.event_id.in_(event_ids)).all()
    campaign_event_ids = [ce.event_id for ce in campaign_events]
    
    # Count by event type
    event_types = {}
    for e in events:
        event_types[e.event_type] = event_types.get(e.event_type, 0) + 1
    
    # Get unique IPs
    unique_ips = set(e.src_ip for e in events)
    
    # Get MITRE techniques
    from .mitre_mapper import map_event_to_mitre
    mitre_techniques = set()
    for e in events:
        mappings = map_event_to_mitre(e, db)
        for m in mappings:
            mitre_techniques.add(m["technique_id"])
    
    # Get high-risk events
    high_risk_events = [e for e in events if e.payload.get("score", 0) > 50]
    
    return {
        "campaign_id": campaign_id,
        "campaign_name": campaign.name,
        "status": campaign.status,
        "total_events": len(events),
        "unique_ips": len(unique_ips),
        "honeypots_count": len(honeypot_ids),
        "event_types": event_types,
        "mitre_techniques_count": len(mitre_techniques),
        "mitre_techniques": list(mitre_techniques),
        "high_risk_events": len(high_risk_events),
        "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
        "ended_at": campaign.ended_at.isoformat() if campaign.ended_at else None,
    }


def link_event_to_campaign(event: models.Event, db: Session):
    """Link an event to its campaign if honeypot belongs to one"""
    honeypot = db.query(models.Honeypot).filter_by(id=event.honeypot_id).first()
    if honeypot and honeypot.campaign_id:
        event.campaign_id = honeypot.campaign_id
        # Also create CampaignEvent link
        existing = db.query(models.CampaignEvent).filter_by(campaign_id=honeypot.campaign_id, event_id=event.id).first()
        if not existing:
            campaign_event = models.CampaignEvent(campaign_id=honeypot.campaign_id, event_id=event.id)
            db.add(campaign_event)
        db.commit()


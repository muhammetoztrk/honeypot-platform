"""Threat Actor Attribution Engine"""
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from . import models


def attribute_threat_actor(ip: str, db: Session) -> dict:
    """Attribute attacks to known threat actors"""
    events = db.query(models.Event).filter_by(src_ip=ip).all()
    
    if not events:
        return {"attributed": False}
    
    # Get MITRE techniques used
    from .mitre_mapper import map_event_to_mitre
    techniques = set()
    for event in events:
        mappings = map_event_to_mitre(event, db)
        for m in mappings:
            techniques.add(m["technique_id"])
    
    # Check against known threat actors
    threat_actors = db.query(models.ThreatActor).all()
    
    matches = []
    for actor in threat_actors:
        actor_techniques = set(actor.techniques or [])
        common_techniques = techniques.intersection(actor_techniques)
        
        if common_techniques:
            score = len(common_techniques) / max(len(actor_techniques), 1) * 100
            matches.append({
                "threat_actor": actor.name,
                "aliases": actor.aliases,
                "common_techniques": list(common_techniques),
                "attribution_score": score,
            })
    
    if matches:
        best_match = max(matches, key=lambda x: x["attribution_score"])
        return {
            "attributed": True,
            "threat_actor": best_match["threat_actor"],
            "attribution_score": best_match["attribution_score"],
            "all_matches": matches,
        }
    
    return {"attributed": False}


def create_threat_actor_profile(name: str, techniques: list, aliases: list, db: Session) -> models.ThreatActor:
    """Create a new threat actor profile"""
    actor = models.ThreatActor(
        name=name,
        techniques=techniques,
        aliases=aliases,
    )
    db.add(actor)
    db.commit()
    db.refresh(actor)
    return actor


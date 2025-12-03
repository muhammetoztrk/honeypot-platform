"""Attack Replay Engine - Session Replay and Timeline"""
from sqlalchemy.orm import Session
from datetime import datetime
from . import models


def get_session_replay(session_id: int, db: Session) -> dict:
    """Get full session replay with timeline"""
    session = db.query(models.Session).filter_by(id=session_id).first()
    if not session:
        return {}
    
    # Get all events for this session, ordered by timestamp
    events = db.query(models.Event).filter_by(session_id=session_id).order_by(models.Event.ts.asc()).all()
    
    # Build timeline
    timeline = []
    for i, event in enumerate(events):
        timeline_item = {
            "index": i + 1,
            "timestamp": event.ts.isoformat(),
            "event_type": event.event_type,
            "payload": event.payload,
        }
        
        # Extract command/action for SSH
        if event.event_type == "ssh_connection":
            commands = event.payload.get("commands", [])
            if commands:
                timeline_item["command"] = commands[-1] if isinstance(commands, list) else commands
            timeline_item["action"] = "Command execution" if commands else "Connection"
        
        # Extract path/method for Web
        elif event.event_type == "web_request":
            timeline_item["path"] = event.payload.get("path", "/")
            timeline_item["method"] = event.payload.get("method", "GET")
            timeline_item["action"] = f"{event.payload.get('method', 'GET')} {event.payload.get('path', '/')}"
        
        # Extract query for Database
        elif event.event_type == "db_query":
            timeline_item["query"] = event.payload.get("query", "")
            timeline_item["action"] = f"Query: {event.payload.get('query', '')[:50]}"
        
        timeline.append(timeline_item)
    
    # Get honeypot info
    honeypot = db.query(models.Honeypot).filter_by(id=session.honeypot_id).first()
    template = None
    if honeypot:
        template = db.query(models.HoneypotTemplate).filter_by(id=honeypot.template_id).first()
    
    return {
        "session_id": session_id,
        "src_ip": session.src_ip,
        "started_at": session.started_at.isoformat(),
        "ended_at": session.ended_at.isoformat() if session.ended_at else None,
        "duration_seconds": (session.ended_at - session.started_at).total_seconds() if session.ended_at else None,
        "total_events": len(events),
        "honeypot_name": honeypot.name if honeypot else "Unknown",
        "honeypot_type": template.type if template else "unknown",
        "timeline": timeline,
    }


def get_session_summary(session_id: int, db: Session) -> dict:
    """Get session summary for quick overview"""
    session = db.query(models.Session).filter_by(id=session_id).first()
    if not session:
        return {}
    
    events = db.query(models.Event).filter_by(session_id=session_id).all()
    
    # Count by event type
    event_types = {}
    for e in events:
        event_types[e.event_type] = event_types.get(e.event_type, 0) + 1
    
    # Extract IOCs
    iocs = []
    for e in events:
        if e.payload.get("username"):
            iocs.append({"type": "username", "value": e.payload["username"]})
        if e.payload.get("password"):
            iocs.append({"type": "password", "value": e.payload["password"]})
        if e.payload.get("url"):
            iocs.append({"type": "url", "value": e.payload["url"]})
    
    return {
        "session_id": session_id,
        "src_ip": session.src_ip,
        "total_events": len(events),
        "event_types": event_types,
        "iocs": iocs,
        "started_at": session.started_at.isoformat(),
    }


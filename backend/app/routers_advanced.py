"""Advanced Features Router - Incidents, MITRE, Playbooks, Tags, etc."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import secrets

from . import models, schemas, auth
from .database import get_db
from .mitre_mapper import get_mitre_statistics, map_event_to_mitre
from .playbook_engine import execute_playbook

router = APIRouter(prefix="/api/v1", tags=["advanced"])


# Incident Management
@router.get("/incidents")
def list_incidents(
    status_filter: str = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    query = db.query(models.Incident)
    if status_filter:
        query = query.filter_by(status=status_filter)
    # Multi-tenant: filter by organization
    if current_user.organization_id:
        query = query.filter_by(organization_id=current_user.organization_id)
    return query.order_by(models.Incident.created_at.desc()).all()


@router.post("/incidents")
def create_incident(
    title: str,
    description: str = None,
    severity: str = "medium",
    event_ids: list = None,
    ioc_ids: list = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    incident = models.Incident(
        title=title,
        description=description,
        severity=severity,
        organization_id=current_user.organization_id,
        created_by=current_user.id,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    
    # Link events
    if event_ids:
        for event_id in event_ids:
            link = models.IncidentEvent(incident_id=incident.id, event_id=event_id)
            db.add(link)
    
    # Link IOCs
    if ioc_ids:
        for ioc_id in ioc_ids:
            link = models.IncidentIOC(incident_id=incident.id, ioc_id=ioc_id)
            db.add(link)
    
    db.commit()
    return incident


@router.put("/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    status: str = None,
    assigned_to: int = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    incident = db.query(models.Incident).filter_by(id=incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    
    if status:
        incident.status = status
    if assigned_to:
        incident.assigned_to = assigned_to
    incident.updated_at = datetime.utcnow()
    db.commit()
    return incident


@router.post("/incidents/{incident_id}/notes")
def add_incident_note(
    incident_id: int,
    note: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    note_obj = models.IncidentNote(incident_id=incident_id, user_id=current_user.id, note=note)
    db.add(note_obj)
    db.commit()
    return note_obj


# MITRE ATT&CK
@router.get("/mitre/statistics")
def get_mitre_stats(
    days: int = 30,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    return get_mitre_statistics(db, days)


@router.get("/events/{event_id}/mitre")
def get_event_mitre(
    event_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    event = db.query(models.Event).filter_by(id=event_id).first()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return map_event_to_mitre(event, db)


# Playbooks
@router.get("/playbooks")
def list_playbooks(db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    return db.query(models.Playbook).order_by(models.Playbook.created_at.desc()).all()


@router.post("/playbooks")
def create_playbook(
    name: str,
    description: str = None,
    trigger_conditions: dict = None,
    steps: list = None,
    enabled: bool = True,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    playbook = models.Playbook(
        name=name,
        description=description,
        trigger_conditions=trigger_conditions or {},
        steps=steps or [],
        enabled=enabled,
        created_by=current_user.id,
    )
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    return playbook


@router.post("/playbooks/{playbook_id}/execute")
def execute_playbook_endpoint(
    playbook_id: int,
    event_id: int = None,
    ioc_id: int = None,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    playbook = db.query(models.Playbook).filter_by(id=playbook_id).first()
    if not playbook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
    
    event = None
    ioc = None
    if event_id:
        event = db.query(models.Event).filter_by(id=event_id).first()
    if ioc_id:
        ioc = db.query(models.IOC).filter_by(id=ioc_id).first()
    
    results = execute_playbook(playbook, event, ioc, db)
    return {"playbook_id": playbook_id, "results": results}


# Tags
@router.get("/tags")
def list_tags(db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    return db.query(models.Tag).all()


@router.post("/tags")
def create_tag(
    name: str,
    color: str = "#22c55e",
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    tag = models.Tag(name=name, color=color)
    db.add(tag)
    db.commit()
    db.refresh(tag)
    return tag


@router.post("/events/{event_id}/tags")
def tag_event(
    event_id: int,
    tag_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    existing = db.query(models.EventTag).filter_by(event_id=event_id, tag_id=tag_id).first()
    if existing:
        return existing
    link = models.EventTag(event_id=event_id, tag_id=tag_id)
    db.add(link)
    db.commit()
    return link


@router.post("/iocs/{ioc_id}/tags")
def tag_ioc(
    ioc_id: int,
    tag_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    existing = db.query(models.IOCTag).filter_by(ioc_id=ioc_id, tag_id=tag_id).first()
    if existing:
        return existing
    link = models.IOCTag(ioc_id=ioc_id, tag_id=tag_id)
    db.add(link)
    db.commit()
    return link


# Share Links
@router.post("/share-links")
def create_share_link(
    resource_type: str,
    resource_id: int = None,
    expires_days: int = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    token = secrets.token_urlsafe(32)
    expires_at = None
    if expires_days:
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
    
    link = models.ShareLink(
        token=token,
        resource_type=resource_type,
        resource_id=resource_id,
        expires_at=expires_at,
        created_by=current_user.id,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return {"token": token, "url": f"/shared/{token}"}


@router.get("/shared/{token}")
def get_shared_resource(
    token: str,
    db: Session = Depends(get_db),
):
    link = db.query(models.ShareLink).filter_by(token=token).first()
    if not link:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Share link not found")
    
    if link.expires_at and link.expires_at < datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Share link expired")
    
    if link.resource_type == "dashboard":
        # Return dashboard data
        stats = {
            "nodes": db.query(models.Node).count(),
            "honeypots": db.query(models.Honeypot).filter_by(status="running").count(),
            "events": db.query(models.Event).count(),
            "iocs": db.query(models.IOC).count(),
        }
        return {"type": "dashboard", "data": stats}
    
    return {"type": link.resource_type, "resource_id": link.resource_id}


# Organizations
@router.get("/organizations")
def list_organizations(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return db.query(models.Organization).all()


@router.post("/organizations")
def create_organization(
    name: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    org = models.Organization(name=name)
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


# Archive Rules
@router.get("/archive-rules")
def list_archive_rules(db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    return db.query(models.ArchiveRule).all()


@router.post("/archive-rules")
def create_archive_rule(
    name: str,
    resource_type: str,
    retention_days: int = 90,
    enabled: bool = True,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    rule = models.ArchiveRule(
        name=name,
        resource_type=resource_type,
        retention_days=retention_days,
        enabled=enabled,
        created_by=current_user.id,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


# Attacker Intelligence
@router.get("/attackers/top")
def get_top_attackers(
    limit: int = 10,
    days: int = 30,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .attacker_intelligence import get_top_attackers
    return get_top_attackers(db, limit, days)


@router.get("/attackers/{ip}")
def get_attacker_profile(
    ip: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    profile = db.query(models.AttackerProfile).filter_by(ip=ip).first()
    if not profile:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attacker profile not found")
    
    # Get recent events
    from datetime import datetime, timedelta
    start_date = datetime.utcnow() - timedelta(days=7)
    events = db.query(models.Event).filter_by(src_ip=ip).filter(models.Event.ts >= start_date).order_by(models.Event.ts.desc()).limit(50).all()
    
    return {
        "ip": profile.ip,
        "risk_score": profile.risk_score,
        "total_events": profile.total_events,
        "honeypots_touched": profile.honeypots_touched,
        "mitre_techniques": profile.mitre_techniques,
        "first_seen": profile.first_seen.isoformat(),
        "last_seen": profile.last_seen.isoformat(),
        "recent_events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "ts": e.ts.isoformat(),
                "honeypot_id": e.honeypot_id,
            }
            for e in events
        ],
    }


# Suppress Rules
@router.get("/suppress-rules")
def list_suppress_rules(db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    return db.query(models.SuppressRule).order_by(models.SuppressRule.created_at.desc()).all()


@router.post("/suppress-rules")
def create_suppress_rule(
    name: str,
    ip: str = None,
    event_type: str = None,
    duration_hours: int = 24,
    enabled: bool = True,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    conditions = {}
    if ip:
        conditions["ip"] = ip
    if event_type:
        conditions["event_type"] = event_type
    conditions["duration_hours"] = duration_hours
    
    rule = models.SuppressRule(
        name=name,
        enabled=enabled,
        conditions=conditions,
        created_by=current_user.id,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/suppress-rules/{rule_id}")
def delete_suppress_rule(rule_id: int, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    rule = db.query(models.SuppressRule).filter_by(id=rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Suppress rule not found")
    db.delete(rule)
    db.commit()
    return {"status": "ok"}


# Campaign Management
@router.get("/campaigns")
def list_campaigns(
    status_filter: str = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    query = db.query(models.Campaign)
    if status_filter:
        query = query.filter_by(status=status_filter)
    # Multi-tenant: filter by organization
    if current_user.organization_id:
        query = query.filter_by(organization_id=current_user.organization_id)
    return query.order_by(models.Campaign.created_at.desc()).all()


@router.post("/campaigns")
def create_campaign(
    name: str,
    description: str = None,
    target_network: str = None,
    honeypot_ids: list = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    campaign = models.Campaign(
        name=name,
        description=description,
        target_network=target_network,
        organization_id=current_user.organization_id,
        created_by=current_user.id,
        status="draft",
    )
    db.add(campaign)
    db.commit()
    db.refresh(campaign)
    
    # Link honeypots to campaign
    if honeypot_ids:
        for hp_id in honeypot_ids:
            # Update honeypot's campaign_id
            honeypot = db.query(models.Honeypot).filter_by(id=hp_id).first()
            if honeypot:
                honeypot.campaign_id = campaign.id
            # Create CampaignHoneypot link
            link = models.CampaignHoneypot(campaign_id=campaign.id, honeypot_id=hp_id)
            db.add(link)
    
    db.commit()
    return campaign


@router.post("/campaigns/{campaign_id}/start")
def start_campaign(
    campaign_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    campaign = db.query(models.Campaign).filter_by(id=campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")
    
    campaign.status = "active"
    campaign.started_at = datetime.utcnow()
    campaign.updated_at = datetime.utcnow()
    db.commit()
    return campaign


@router.post("/campaigns/{campaign_id}/stop")
def stop_campaign(
    campaign_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    campaign = db.query(models.Campaign).filter_by(id=campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")
    
    campaign.status = "paused"
    campaign.ended_at = datetime.utcnow()
    campaign.updated_at = datetime.utcnow()
    db.commit()
    return campaign


@router.get("/campaigns/{campaign_id}/statistics")
def get_campaign_statistics_endpoint(
    campaign_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .campaign_engine import get_campaign_statistics
    stats = get_campaign_statistics(campaign_id, db)
    if not stats:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")
    return stats


@router.put("/campaigns/{campaign_id}")
def update_campaign(
    campaign_id: int,
    name: str = None,
    description: str = None,
    target_network: str = None,
    status: str = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    campaign = db.query(models.Campaign).filter_by(id=campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")
    
    if name:
        campaign.name = name
    if description is not None:
        campaign.description = description
    if target_network:
        campaign.target_network = target_network
    if status:
        campaign.status = status
    campaign.updated_at = datetime.utcnow()
    db.commit()
    return campaign


@router.delete("/campaigns/{campaign_id}")
def delete_campaign(
    campaign_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    campaign = db.query(models.Campaign).filter_by(id=campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")
    
    # Delete campaign links
    db.query(models.CampaignHoneypot).filter_by(campaign_id=campaign_id).delete()
    db.query(models.CampaignEvent).filter_by(campaign_id=campaign_id).delete()
    
    # Remove campaign_id from honeypots
    db.query(models.Honeypot).filter_by(campaign_id=campaign_id).update({"campaign_id": None})
    
    db.delete(campaign)
    db.commit()
    return {"status": "ok"}


# Attack Replay
@router.get("/sessions/{session_id}/replay")
def get_session_replay(
    session_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .attack_replay import get_session_replay
    replay = get_session_replay(session_id, db)
    if not replay:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    return replay


@router.get("/sessions/{session_id}/summary")
def get_session_summary(
    session_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .attack_replay import get_session_summary
    summary = get_session_summary(session_id, db)
    if not summary:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    return summary


# Detection Lab
@router.get("/detection-lab/scenarios")
def list_detection_scenarios(
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    return db.query(models.DetectionLabScenario).filter_by(enabled=True).all()


@router.post("/detection-lab/scenarios/{scenario_id}/check")
def check_detection_scenario(
    scenario_id: int,
    session_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .detection_lab import check_scenario
    result = check_scenario(session_id, scenario_id, db)
    return result


@router.post("/detection-lab/scenarios/seed")
def seed_detection_scenarios(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    from .detection_lab import seed_detection_lab_scenarios
    seed_detection_lab_scenarios(db)
    return {"status": "ok", "message": "Detection lab scenarios seeded"}


# Behavioral Analysis
@router.get("/behavioral-analysis/{ip}")
def analyze_attacker(
    ip: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .behavioral_analysis import analyze_attacker_behavior
    return analyze_attacker_behavior(ip, db)


@router.get("/behavioral-analysis/{ip}/brute-force")
def check_brute_force(
    ip: str,
    time_window: int = 300,
    min_attempts: int = 5,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .behavioral_analysis import detect_brute_force
    return detect_brute_force(ip, db, time_window, min_attempts)


@router.get("/behavioral-analysis/{ip}/port-scan")
def check_port_scan(
    ip: str,
    time_window: int = 60,
    min_ports: int = 3,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .behavioral_analysis import detect_port_scan
    return detect_port_scan(ip, db, time_window, min_ports)


@router.get("/behavioral-analysis/{ip}/credential-stuffing")
def check_credential_stuffing(
    ip: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .behavioral_analysis import detect_credential_stuffing
    return detect_credential_stuffing(ip, db)


# ML Anomaly Detection
@router.get("/ml-anomaly/{ip}")
def check_ml_anomaly(
    ip: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .ml_anomaly_detection import detect_ml_anomaly, detect_attack_chain
    anomaly = detect_ml_anomaly(ip, db)
    chain = detect_attack_chain(ip, db)
    return {"anomaly": anomaly, "attack_chain": chain}


# Auto-Response
@router.post("/auto-response/execute")
def execute_auto_response_endpoint(
    trigger_type: str,
    ip: str,
    details: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    from .auto_response import execute_auto_response
    responses = execute_auto_response(trigger_type, ip, details, db, current_user.id)
    return {"status": "ok", "responses": len(responses)}


# Threat Intelligence Feeds
@router.get("/threat-intel/feeds")
def list_threat_intel_feeds(
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    return db.query(models.ThreatIntelFeed).all()


@router.post("/threat-intel/feeds")
def create_threat_intel_feed(
    name: str,
    source: str,
    api_key: str = None,
    enabled: bool = True,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    feed = models.ThreatIntelFeed(
        name=name,
        source=source,
        api_key=api_key,
        enabled=enabled,
    )
    db.add(feed)
    db.commit()
    db.refresh(feed)
    return feed


@router.post("/threat-intel/enrich")
def enrich_ioc_with_feeds(
    ioc_type: str,
    value: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .threat_intel_feeds import enrich_with_feeds
    return enrich_with_feeds(ioc_type, value, db)


# Honeypot Health Monitoring
@router.get("/honeypots/{hp_id}/health")
def get_honeypot_health(
    hp_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    health = db.query(models.HoneypotHealth).filter_by(honeypot_id=hp_id).order_by(models.HoneypotHealth.last_check.desc()).first()
    if not health:
        return {"status": "unknown", "message": "No health data available"}
    return health


# Geo-Blocking
@router.get("/geo-block-rules")
def list_geo_block_rules(
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    return db.query(models.GeoBlockRule).all()


@router.post("/geo-block-rules")
def create_geo_block_rule(
    name: str,
    action: str,
    countries: list,
    enabled: bool = True,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    rule = models.GeoBlockRule(
        name=name,
        action=action,
        countries=countries,
        enabled=enabled,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


# Time-Based Rules
@router.get("/time-based-rules")
def list_time_based_rules(
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    return db.query(models.TimeBasedRule).all()


@router.post("/time-based-rules")
def create_time_based_rule(
    name: str,
    action: str,
    time_window: dict,
    enabled: bool = True,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    rule = models.TimeBasedRule(
        name=name,
        action=action,
        time_window=time_window,
        enabled=enabled,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


# SIEM Integration
@router.get("/siem-integrations")
def list_siem_integrations(
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    return db.query(models.SIEMIntegration).all()


@router.post("/siem-integrations")
def create_siem_integration(
    name: str,
    siem_type: str,
    endpoint: str,
    api_key: str = None,
    enabled: bool = True,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    integration = models.SIEMIntegration(
        name=name,
        siem_type=siem_type,
        endpoint=endpoint,
        api_key=api_key,
        enabled=enabled,
    )
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


@router.post("/siem-integrations/{integration_id}/test")
def test_siem_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    integration = db.query(models.SIEMIntegration).filter_by(id=integration_id).first()
    if not integration:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SIEM integration not found")
    
    from .siem_integration import send_to_siem
    from . import models as m
    
    # Create a test event
    test_event = m.Event(
        id=0,  # Dummy ID
        session_id=0,
        honeypot_id=0,
        src_ip="192.0.2.1",
        dst_port=22,
        event_type="test_event",
        payload={"test": True},
        ts=datetime.utcnow(),
    )
    
    result = send_to_siem(test_event, integration, db)
    return {"status": "ok", "test_result": result}


# Compliance Reports
@router.get("/compliance-reports")
def list_compliance_reports(
    compliance_type: str = None,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    query = db.query(models.ComplianceReport)
    if compliance_type:
        query = query.filter_by(compliance_type=compliance_type)
    return query.order_by(models.ComplianceReport.generated_at.desc()).all()


@router.post("/compliance-reports/generate")
def generate_compliance_report(
    compliance_type: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    # Generate compliance report data
    report_data = {
        "compliance_type": compliance_type,
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {},
    }
    
    if compliance_type == "gdpr":
        # GDPR compliance data
        events = db.query(models.Event).count()
        iocs = db.query(models.IOC).count()
        report_data["summary"] = {
            "total_events": events,
            "total_iocs": iocs,
            "data_retention_days": 90,
        }
    elif compliance_type == "hipaa":
        # HIPAA compliance data
        report_data["summary"] = {
            "access_logs": db.query(models.Session).count(),
            "audit_trail": True,
        }
    elif compliance_type == "pci_dss":
        # PCI-DSS compliance data
        report_data["summary"] = {
            "network_segmentation": True,
            "monitoring": True,
        }
    elif compliance_type == "iso27001":
        # ISO 27001 compliance data
        report_data["summary"] = {
            "security_controls": True,
            "incident_management": db.query(models.Incident).count(),
        }
    
    report = models.ComplianceReport(
        name=f"{compliance_type.upper()} Compliance Report",
        compliance_type=compliance_type,
        report_data=report_data,
        created_by=current_user.id,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


# Backup and Restore
@router.post("/backups/create")
def create_backup(
    backup_name: str = None,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .backup_service import BackupService
    from .database import engine
    
    backup_service = BackupService()
    db_url = str(engine.url)
    result = backup_service.create_backup(db_url, backup_name)
    
    if result["status"] == "success":
        # Record backup in database
        backup = models.Backup(
            name=result["backup_name"],
            backup_path=result["backup_path"],
            size_bytes=result["size_bytes"],
        )
        db.add(backup)
        db.commit()
        db.refresh(backup)
        result["backup_id"] = backup.id
    
    return result


@router.get("/backups")
def list_backups(
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .backup_service import BackupService
    backup_service = BackupService()
    return backup_service.list_backups()


@router.post("/backups/{backup_name}/restore")
def restore_backup(
    backup_name: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .backup_service import BackupService
    from .database import engine
    
    backup_service = BackupService()
    db_url = str(engine.url)
    result = backup_service.restore_backup(backup_name, db_url)
    
    # Clear cache after restore
    from .performance import cache_clear
    cache_clear()
    
    return result


@router.post("/backups/cleanup")
def cleanup_backups(
    keep_days: int = 30,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .backup_service import BackupService
    backup_service = BackupService()
    deleted = backup_service.cleanup_old_backups(keep_days)
    return {"deleted": deleted, "count": len(deleted)}


# Performance and Monitoring
@router.get("/system/health")
def get_system_health(
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .monitoring import HealthChecker
    return HealthChecker.full_health_check(db)


@router.get("/system/metrics")
def get_system_metrics(
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from .performance import get_cached_metrics
    return get_cached_metrics(db)


@router.post("/cache/clear")
def clear_cache(
    pattern: str = None,
    _: models.User = Depends(auth.get_current_user),
):
    from .performance import cache_clear
    cache_clear(pattern)
    return {"status": "success", "message": "Cache cleared"}


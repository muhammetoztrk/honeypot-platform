from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from . import models, schemas, auth
from .database import get_db

router = APIRouter(prefix="/api/v1", tags=["core"])


@router.get("/me", response_model=schemas.UserRead)
def read_me(current_user: models.User = Depends(auth.get_current_user)):
    return current_user


@router.post("/nodes", response_model=schemas.NodeRead)
def create_node(node_in: schemas.NodeCreate, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    import secrets

    api_key = secrets.token_hex(32)
    node = models.Node(name=node_in.name, api_key=api_key)
    db.add(node)
    db.commit()
    db.refresh(node)
    return node


@router.get("/nodes", response_model=list[schemas.NodeRead])
def list_nodes(db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    return db.query(models.Node).all()


@router.get("/nodes/{node_id}", response_model=schemas.NodeRead)
def get_node(node_id: int, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    from fastapi import HTTPException, status
    node = db.query(models.Node).filter_by(id=node_id).first()
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    return node


@router.get("/templates", response_model=list[schemas.HoneypotTemplateRead])
def list_templates(db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    return db.query(models.HoneypotTemplate).all()


@router.delete("/nodes/{node_id}")
def delete_node(node_id: int, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    from fastapi import HTTPException, status
    from .honeypot_services import HoneypotManager

    node = db.query(models.Node).filter_by(id=node_id).first()
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")

    # Get all honeypots on this node
    honeypots = db.query(models.Honeypot).filter_by(node_id=node_id).all()
    
    # Stop all honeypots and delete related data
    for hp in honeypots:
        HoneypotManager.stop(hp.id)
        # Delete events for this honeypot
        db.query(models.Event).filter_by(honeypot_id=hp.id).delete()
        # Delete sessions for this honeypot
        db.query(models.Session).filter_by(honeypot_id=hp.id).delete()
        # Delete honeypot
        db.delete(hp)

    # Delete node
    db.delete(node)
    db.commit()
    return {"status": "ok", "message": "Node deleted"}


@router.post("/honeypots", response_model=schemas.HoneypotRead)
def create_honeypot(hp_in: schemas.HoneypotCreate, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    hp = models.Honeypot(
        node_id=hp_in.node_id,
        template_id=hp_in.template_id,
        name=hp_in.name,
        listen_ip=hp_in.listen_ip,
        listen_port=hp_in.listen_port,
    )
    db.add(hp)
    db.commit()
    db.refresh(hp)
    return hp


@router.get("/honeypots", response_model=list[schemas.HoneypotRead])
def list_honeypots(db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    return db.query(models.Honeypot).all()


@router.delete("/honeypots/{hp_id}")
def delete_honeypot(hp_id: int, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    from fastapi import HTTPException, status
    from .honeypot_services import HoneypotManager

    hp = db.query(models.Honeypot).filter_by(id=hp_id).first()
    if not hp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Honeypot not found")

    # Stop honeypot if running
    HoneypotManager.stop(hp.id)

    # Delete related sessions and events
    db.query(models.Event).filter_by(honeypot_id=hp_id).delete()
    db.query(models.Session).filter_by(honeypot_id=hp_id).delete()

    # Delete honeypot
    db.delete(hp)
    db.commit()
    return {"status": "ok", "message": "Honeypot deleted"}


@router.get("/honeypots/{hp_id}", response_model=schemas.HoneypotRead)
def get_honeypot(hp_id: int, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    hp = db.query(models.Honeypot).filter_by(id=hp_id).first()
    if not hp:
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Honeypot not found")
    return hp


@router.post("/honeypots/{hp_id}/start", response_model=schemas.HoneypotRead)
def start_honeypot(hp_id: int, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    from fastapi import HTTPException, status
    from .honeypot_services import HoneypotManager
    import os

    hp = db.query(models.Honeypot).filter_by(id=hp_id).first()
    if not hp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Honeypot not found")

    node = db.query(models.Node).filter_by(id=hp.node_id).first()
    if not node:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Node not found")

    template = db.query(models.HoneypotTemplate).filter_by(id=hp.template_id).first()
    if not template:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Template not found")

    # Start honeypot service
    api_url = os.getenv("API_URL", "http://localhost:8000")
    service = HoneypotManager.get_or_create(
        hp.id,
        template.type,
        hp.listen_ip,
        hp.listen_port,
        api_url,
        node.api_key,
    )
    service.start()

    hp.status = "running"
    db.commit()
    db.refresh(hp)
    return hp


@router.post("/honeypots/{hp_id}/stop", response_model=schemas.HoneypotRead)
def stop_honeypot(hp_id: int, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    from fastapi import HTTPException, status
    from .honeypot_services import HoneypotManager

    hp = db.query(models.Honeypot).filter_by(id=hp_id).first()
    if not hp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Honeypot not found")

    # Stop honeypot service
    HoneypotManager.stop(hp.id)

    hp.status = "stopped"
    db.commit()
    db.refresh(hp)
    return hp


@router.get("/sessions", response_model=list[schemas.SessionRead])
def list_sessions(
    limit: int = 100,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    return db.query(models.Session).order_by(models.Session.started_at.desc()).limit(limit).all()


@router.get("/events", response_model=list[schemas.EventRead])
def list_events(
    limit: int = 100,
    honeypot_id: int = None,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    q = db.query(models.Event)
    if honeypot_id:
        q = q.filter_by(honeypot_id=honeypot_id)
    return q.order_by(models.Event.ts.desc()).limit(limit).all()


@router.get("/iocs", response_model=list[schemas.IOCRead])
def list_iocs(
    limit: int = 100,
    ioc_type: str = None,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    q = db.query(models.IOC)
    if ioc_type:
        q = q.filter_by(ioc_type=ioc_type)
    return q.order_by(models.IOC.score.desc(), models.IOC.last_seen.desc()).limit(limit).all()


@router.get("/iocs/{ioc_id}", response_model=schemas.IOCRead)
def get_ioc(ioc_id: int, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    from fastapi import HTTPException, status
    ioc = db.query(models.IOC).filter_by(id=ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")
    return ioc


@router.post("/agent/heartbeat")
def agent_heartbeat(heartbeat: schemas.AgentHeartbeat, db: Session = Depends(get_db)):
    node = db.query(models.Node).filter_by(api_key=heartbeat.api_key).first()
    if not node:
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    from datetime import datetime
    node.last_heartbeat_at = datetime.utcnow()
    db.commit()
    return {"status": "ok"}


@router.post("/agent/event")
def agent_submit_event(event: schemas.AgentEventSubmit, db: Session = Depends(get_db)):
    from datetime import datetime
    # Import models locally to avoid UnboundLocalError
    from . import models
    node = db.query(models.Node).filter_by(api_key=event.api_key).first()
    if not node:
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    # Find or create session
    session = (
        db.query(models.Session)
        .filter_by(
            honeypot_id=event.honeypot_id,
            src_ip=event.src_ip,
            ended_at=None,
        )
        .first()
    )
    if not session:
        # Use protocol and timestamp from event if provided
        protocol = getattr(event, 'protocol', 'tcp')
        timestamp = getattr(event, 'timestamp', None)
        if timestamp:
            if isinstance(timestamp, str):
                try:
                    started_at = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except:
                    started_at = datetime.utcnow()
            else:
                started_at = timestamp
        else:
            started_at = datetime.utcnow()
        session = models.Session(
            honeypot_id=event.honeypot_id,
            src_ip=event.src_ip,
            src_port=event.src_port,
            protocol=protocol,
            started_at=started_at,
        )
        db.add(session)
        db.commit()
        db.refresh(session)

    # Create event
    # Use timestamp from event if provided
    timestamp = getattr(event, 'timestamp', None)
    if timestamp:
        if isinstance(timestamp, str):
            try:
                event_ts = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                event_ts = datetime.utcnow()
        else:
            event_ts = timestamp
    else:
        event_ts = datetime.utcnow()
    evt = models.Event(
        session_id=session.id,
        honeypot_id=event.honeypot_id,
        src_ip=event.src_ip,
        dst_port=event.src_port,  # Use src_port as dst_port for honeypot
        event_type=event.event_type,
        payload=event.payload,
        ts=event_ts,
    )
    db.add(evt)

    # Extract IOCs
    from .ioc_extractor import extract_iocs
    extract_iocs(evt, db)

    # Check for high-risk events and create alerts
    from .alert_service import check_and_create_alerts
    check_and_create_alerts(evt, db)

    # Evaluate alert rules
    from .alert_rules_engine import evaluate_alert_rules
    evaluate_alert_rules(event=evt, db=db)
    
    # Execute playbooks
    from .playbook_engine import execute_playbook
    playbooks = db.query(models.Playbook).filter_by(enabled=True).all()
    for playbook in playbooks:
        execute_playbook(playbook, event=evt, db=db)
    
    # Update attacker profile
    from .attacker_intelligence import update_attacker_profile
    update_attacker_profile(evt.src_ip, evt, db)
    
    # Link event to campaign
    from .campaign_engine import link_event_to_campaign
    link_event_to_campaign(evt, db)
    
    # Behavioral analysis (async check)
    try:
        from .behavioral_analysis import analyze_attacker_behavior
        analyze_attacker_behavior(evt.src_ip, db)
    except Exception:
        pass  # Don't fail event creation if analysis fails
    
    # Send to SIEM integrations
    try:
        from .siem_integration import send_event_to_all_siems
        send_event_to_all_siems(evt, db)
    except Exception:
        pass  # Don't fail event creation if SIEM send fails
    
    # Check rate limits
    try:
        from .rate_limiter import RateLimiter
        rate_result = RateLimiter.check_ip_rate_limit(evt.src_ip, db)
        if rate_result.get("blocked"):
            # Auto-block IP
            from .auto_response import auto_block_ip
            auto_block_ip(evt.src_ip, "Rate limit exceeded", db)
    except Exception:
        pass
    
    # Check YARA rules
    try:
        from .yara_engine import check_event_yara
        check_event_yara(evt, db)
    except Exception:
        pass
    
    # Check honeytokens
    try:
        from .honeytoken_manager import check_honeytoken_trigger
        payload_str = str(evt.payload)
        honeytoken_result = check_honeytoken_trigger(payload_str, db)
        if honeytoken_result.get("triggered"):
            # Create high-severity alert
            from .alert_service import create_alert
            create_alert(
                severity="critical",
                title=f"Honeytoken Triggered: {honeytoken_result['token_name']}",
                message=f"Honeytoken '{honeytoken_result['token_name']}' was triggered by {evt.src_ip}",
                event_id=evt.id,
                db=db,
            )
    except Exception:
        pass

    db.commit()
    return {"status": "ok", "session_id": session.id, "event_id": evt.id}


@router.get("/alerts", response_model=list[schemas.AlertRead])
def list_alerts(
    limit: int = 50,
    unread_only: bool = False,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    q = db.query(models.Alert)
    if unread_only:
        q = q.filter_by(read=False)
    return q.order_by(models.Alert.created_at.desc()).limit(limit).all()


@router.post("/alerts/{alert_id}/read")
def mark_alert_read(
    alert_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from fastapi import HTTPException, status
    alert = db.query(models.Alert).filter_by(id=alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    alert.read = True
    db.commit()
    return {"status": "ok"}


# WebSocket endpoint
@router.websocket("/ws")
async def websocket_endpoint(websocket):
    from .websocket_manager import manager
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo back or handle commands
            await manager.send_personal_message({"type": "pong", "data": data}, websocket)
    except Exception:
        pass
    finally:
        manager.disconnect(websocket)


# IP Blocking endpoints
@router.get("/blocked-ips")
def list_blocked_ips(db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    return db.query(models.BlockedIP).order_by(models.BlockedIP.blocked_at.desc()).all()


def _block_ip_internal(ip: str, reason: str, db: Session, user_id: int = None):
    """Internal function to block IP (used by alert rules)"""
    existing = db.query(models.BlockedIP).filter_by(ip=ip).first()
    if existing:
        return existing
    
    blocked = models.BlockedIP(ip=ip, reason=reason, blocked_by=user_id)
    db.add(blocked)
    db.commit()
    
    # Broadcast via WebSocket
    try:
        from .websocket_manager import manager
        import asyncio
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(manager.broadcast({
                "type": "ip_blocked",
                "ip": ip,
                "reason": reason
            }))
        else:
            loop.run_until_complete(manager.broadcast({
                "type": "ip_blocked",
                "ip": ip,
                "reason": reason
            }))
    except Exception:
        pass
    
    return blocked


@router.post("/blocked-ips")
def block_ip(ip: str, reason: str, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    from fastapi import HTTPException, status
    
    existing = db.query(models.BlockedIP).filter_by(ip=ip).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="IP already blocked")
    
    _block_ip_internal(ip, reason, db, current_user.id)
    return {"status": "ok", "message": f"IP {ip} blocked"}


@router.delete("/blocked-ips/{ip}")
def unblock_ip(ip: str, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    from fastapi import HTTPException, status
    blocked = db.query(models.BlockedIP).filter_by(ip=ip).first()
    if not blocked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP not found")
    db.delete(blocked)
    db.commit()
    return {"status": "ok", "message": f"IP {ip} unblocked"}


# IOC Enrichment endpoints
@router.post("/iocs/{ioc_id}/enrich")
def enrich_ioc(ioc_id: int, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    from fastapi import HTTPException, status
    from .threat_intel import ThreatIntelligence
    
    ioc = db.query(models.IOC).filter_by(id=ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")
    
    # Enrich based on type
    if ioc.ioc_type == "ip":
        enrichment_data = ThreatIntelligence.enrich_ip(ioc.value)
    elif ioc.ioc_type == "url":
        enrichment_data = ThreatIntelligence.enrich_url(ioc.value)
    elif ioc.ioc_type == "hash":
        enrichment_data = ThreatIntelligence.enrich_hash(ioc.value)
    else:
        enrichment_data = {"source": "unknown", "is_malicious": False}
    
    # Store enrichment
    enrichment = models.IOCEnrichment(
        ioc_id=ioc_id,
        source=enrichment_data.get("source", "unknown"),
        data=enrichment_data
    )
    db.add(enrichment)
    db.commit()
    
    return {"status": "ok", "enrichment": enrichment_data}


@router.get("/iocs/{ioc_id}/enrichments")
def get_ioc_enrichments(ioc_id: int, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    enrichments = db.query(models.IOCEnrichment).filter_by(ioc_id=ioc_id).order_by(models.IOCEnrichment.enriched_at.desc()).all()
    return enrichments


# Reporting endpoints
@router.get("/reports/events")
def generate_events_report(
    format: str = "html",
    start_date: str = None,
    end_date: str = None,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from fastapi.responses import HTMLResponse, Response, StreamingResponse
    from datetime import datetime
    from .pdf_report import generate_pdf_report
    
    query = db.query(models.Event)
    if start_date:
        query = query.filter(models.Event.ts >= datetime.fromisoformat(start_date))
    if end_date:
        query = query.filter(models.Event.ts <= datetime.fromisoformat(end_date))
    
    events = query.order_by(models.Event.ts.desc()).limit(1000).all()
    
    # Get stats
    nodes_count = db.query(models.Node).count()
    honeypots_count = db.query(models.Honeypot).filter_by(status="running").count()
    iocs = db.query(models.IOC).order_by(models.IOC.score.desc()).limit(100).all()
    
    stats = {
        "nodes": nodes_count,
        "honeypots": honeypots_count,
        "events": len(events),
        "iocs": len(iocs),
    }
    
    if format == "pdf":
        # Generate PDF report
        events_data = [{
            "id": e.id,
            "ts": e.ts.isoformat() if hasattr(e.ts, 'isoformat') else str(e.ts),
            "src_ip": e.src_ip,
            "event_type": e.event_type,
            "payload": e.payload,
        } for e in events]
        
        iocs_data = [{
            "id": i.id,
            "ioc_type": i.ioc_type,
            "value": i.value,
            "score": i.score,
            "seen_count": i.seen_count,
            "first_seen": i.first_seen.isoformat() if hasattr(i.first_seen, 'isoformat') else str(i.first_seen),
        } for i in iocs]
        
        pdf_buffer = generate_pdf_report(events_data, iocs_data, stats)
        
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"}
        )
    elif format == "html":
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Events Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                h1 {{ color: #2c3e50; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #3498db; color: white; }}
                tr:nth-child(even) {{ background-color: #f8f9fa; }}
                .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
                .stat-box {{ background: #ecf0f1; padding: 15px; border-radius: 6px; flex: 1; }}
                .stat-value {{ font-size: 24px; font-weight: bold; color: #2c3e50; }}
                .stat-label {{ font-size: 12px; color: #7f8c8d; margin-top: 5px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Security Events Report</h1>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="stats">
                    <div class="stat-box">
                        <div class="stat-value">{stats['events']}</div>
                        <div class="stat-label">Total Events</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{stats['iocs']}</div>
                        <div class="stat-label">IOCs Detected</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{stats['honeypots']}</div>
                        <div class="stat-label">Active Honeypots</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">{stats['nodes']}</div>
                        <div class="stat-label">Online Nodes</div>
                    </div>
                </div>
                
                <h2>Recent Events</h2>
                <table>
                    <tr>
                        <th>Time</th>
                        <th>Source IP</th>
                        <th>Type</th>
                        <th>Details</th>
                    </tr>
                    {"".join([f"<tr><td>{e.ts}</td><td>{e.src_ip}</td><td>{e.event_type}</td><td>{str(e.payload)[:100]}</td></tr>" for e in events[:50]])}
                </table>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(content=html)
    else:
        # JSON format
        return {"events": [{"id": e.id, "ts": e.ts.isoformat(), "src_ip": e.src_ip, "event_type": e.event_type, "payload": e.payload} for e in events]}


# Log viewer endpoint
@router.get("/logs")
def get_logs(limit: int = 100, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    import subprocess
    import os
    
    # Get recent events as "logs"
    events = db.query(models.Event).order_by(models.Event.ts.desc()).limit(limit).all()
    
    logs = []
    for event in events:
        logs.append({
            "timestamp": event.ts.isoformat(),
            "level": "INFO",
            "message": f"{event.event_type} from {event.src_ip}",
            "details": event.payload
        })
    
    return {"logs": logs}


# Alert Rules endpoints
@router.get("/alert-rules")
def list_alert_rules(db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    return db.query(models.AlertRule).order_by(models.AlertRule.created_at.desc()).all()


@router.post("/alert-rules")
def create_alert_rule(
    name: str,
    enabled: bool = True,
    conditions: dict = None,
    actions: dict = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    rule = models.AlertRule(
        name=name,
        enabled=enabled,
        conditions=conditions or {},
        actions=actions or {},
        created_by=current_user.id,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.put("/alert-rules/{rule_id}")
def update_alert_rule(
    rule_id: int,
    name: str = None,
    enabled: bool = None,
    conditions: dict = None,
    actions: dict = None,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from fastapi import HTTPException, status
    rule = db.query(models.AlertRule).filter_by(id=rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    if name is not None:
        rule.name = name
    if enabled is not None:
        rule.enabled = enabled
    if conditions is not None:
        rule.conditions = conditions
    if actions is not None:
        rule.actions = actions
    db.commit()
    return rule


@router.delete("/alert-rules/{rule_id}")
def delete_alert_rule(rule_id: int, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    from fastapi import HTTPException, status
    rule = db.query(models.AlertRule).filter_by(id=rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    db.delete(rule)
    db.commit()
    return {"status": "ok"}


# Scheduled Reports endpoints
@router.get("/scheduled-reports")
def list_scheduled_reports(db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    return db.query(models.ScheduledReport).order_by(models.ScheduledReport.created_at.desc()).all()


@router.post("/scheduled-reports")
def create_scheduled_report(
    name: str,
    schedule_type: str,
    format: str = "pdf",
    recipients: list = None,
    enabled: bool = True,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    from datetime import datetime, timedelta
    now = datetime.utcnow()
    if schedule_type == "daily":
        next_run = now + timedelta(days=1)
    elif schedule_type == "weekly":
        next_run = now + timedelta(weeks=1)
    elif schedule_type == "monthly":
        next_run = now + timedelta(days=30)
    else:
        next_run = now + timedelta(days=1)
    
    report = models.ScheduledReport(
        name=name,
        enabled=enabled,
        schedule_type=schedule_type,
        format=format,
        recipients=recipients or [],
        next_run=next_run,
        created_by=current_user.id,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.delete("/scheduled-reports/{report_id}")
def delete_scheduled_report(report_id: int, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    from fastapi import HTTPException, status
    report = db.query(models.ScheduledReport).filter_by(id=report_id).first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled report not found")
    db.delete(report)
    db.commit()
    return {"status": "ok"}


# Webhook endpoints
@router.get("/webhooks")
def list_webhooks(db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    return db.query(models.WebhookConfig).order_by(models.WebhookConfig.created_at.desc()).all()


@router.post("/webhooks")
def create_webhook(
    name: str,
    url: str,
    type: str = "generic",
    events: list = None,
    enabled: bool = True,
    secret: str = None,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    webhook = models.WebhookConfig(
        name=name,
        url=url,
        type=type,
        events=events or [],
        enabled=enabled,
        secret=secret,
    )
    db.add(webhook)
    db.commit()
    db.refresh(webhook)
    return webhook


@router.delete("/webhooks/{webhook_id}")
def delete_webhook(webhook_id: int, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    from fastapi import HTTPException, status
    webhook = db.query(models.WebhookConfig).filter_by(id=webhook_id).first()
    if not webhook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    db.delete(webhook)
    db.commit()
    return {"status": "ok"}


@router.post("/webhooks/{webhook_id}/test")
def test_webhook(webhook_id: int, db: Session = Depends(get_db), _: models.User = Depends(auth.get_current_user)):
    from fastapi import HTTPException, status
    import requests
    webhook = db.query(models.WebhookConfig).filter_by(id=webhook_id).first()
    if not webhook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    
    test_payload = {"test": True, "message": "Test webhook from Honeypot Platform"}
    try:
        response = requests.post(webhook.url, json=test_payload, timeout=5)
        return {"status": "ok", "response_status": response.status_code}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# User Management endpoints
@router.get("/users")
def list_users(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    # Only admins can list users
    if current_user.role != "admin":
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return db.query(models.User).all()


@router.post("/users")
def create_user(
    email: str,
    password: str,
    role: str = "viewer",
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    from fastapi import HTTPException, status
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    
    existing = db.query(models.User).filter_by(email=email).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
    
    from .auth import hash_password
    user = models.User(email=email, password_hash=hash_password(password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "email": user.email, "role": user.role}


@router.put("/users/{user_id}/role")
def update_user_role(
    user_id: int,
    role: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    from fastapi import HTTPException, status
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    
    user = db.query(models.User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    user.role = role
    db.commit()
    return {"status": "ok"}


# Backup/Restore endpoints
@router.post("/backup/create")
def create_backup(
    backup_type: str = "full",
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    from fastapi import HTTPException, status
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    
    import json
    from datetime import datetime
    
    backup_data = {}
    if backup_type == "full" or backup_type == "events":
        events = db.query(models.Event).limit(10000).all()
        backup_data["events"] = [{"id": e.id, "ts": e.ts.isoformat(), "src_ip": e.src_ip, "event_type": e.event_type, "payload": e.payload} for e in events]
    
    if backup_type == "full" or backup_type == "iocs":
        iocs = db.query(models.IOC).all()
        backup_data["iocs"] = [{"id": i.id, "ioc_type": i.ioc_type, "value": i.value, "score": i.score, "seen_count": i.seen_count} for i in iocs]
    
    filename = f"backup_{backup_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    backup = models.Backup(
        filename=filename,
        size_bytes=len(json.dumps(backup_data)),
        backup_type=backup_type,
        created_by=current_user.id,
    )
    db.add(backup)
    db.commit()
    
    return {"status": "ok", "backup_id": backup.id, "filename": filename, "data": backup_data}


@router.get("/backups")
def list_backups(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    if current_user.role != "admin":
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return db.query(models.Backup).order_by(models.Backup.created_at.desc()).limit(50).all()


# Custom Template endpoints
@router.post("/templates")
def create_template(
    name: str,
    type: str,
    default_config: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    if current_user.role != "admin":
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    
    template = models.HoneypotTemplate(name=name, type=type, default_config=default_config)
    db.add(template)
    db.commit()
    db.refresh(template)
    return template


@router.put("/templates/{template_id}")
def update_template(
    template_id: int,
    name: str = None,
    default_config: dict = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    from fastapi import HTTPException, status
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    
    template = db.query(models.HoneypotTemplate).filter_by(id=template_id).first()
    if not template:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")
    
    if name is not None:
        template.name = name
    if default_config is not None:
        template.default_config = default_config
    db.commit()
    return template


@router.delete("/templates/{template_id}")
def delete_template(template_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    from fastapi import HTTPException, status
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    
    template = db.query(models.HoneypotTemplate).filter_by(id=template_id).first()
    if not template:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")
    
    db.delete(template)
    db.commit()
    return {"status": "ok"}


# Advanced Analytics endpoints
@router.get("/analytics/trends")
def get_analytics_trends(
    days: int = 7,
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from datetime import datetime, timedelta
    from collections import Counter
    
    start_date = datetime.utcnow() - timedelta(days=days)
    events = db.query(models.Event).filter(models.Event.ts >= start_date).all()
    iocs = db.query(models.IOC).filter(models.IOC.first_seen >= start_date).all()
    
    # Event trends
    event_types = Counter([e.event_type for e in events])
    ip_activity = Counter([e.src_ip for e in events])
    
    # IOC trends
    ioc_types = Counter([i.ioc_type for i in iocs])
    high_risk_iocs = [i for i in iocs if i.score > 70]
    
    # Anomaly detection (simple)
    hourly_events = {}
    for e in events:
        hour = e.ts.replace(minute=0, second=0, microsecond=0)
        hourly_events[hour] = hourly_events.get(hour, 0) + 1
    
    avg_events_per_hour = sum(hourly_events.values()) / len(hourly_events) if hourly_events else 0
    anomalies = [{"hour": str(h), "count": c} for h, c in hourly_events.items() if c > avg_events_per_hour * 2]
    
    return {
        "event_types": dict(event_types),
        "top_ips": dict(ip_activity.most_common(10)),
        "ioc_types": dict(ioc_types),
        "high_risk_iocs_count": len(high_risk_iocs),
        "anomalies": anomalies,
        "total_events": len(events),
        "total_iocs": len(iocs),
    }


@router.get("/analytics/patterns")
def get_attack_patterns(
    db: Session = Depends(get_db),
    _: models.User = Depends(auth.get_current_user),
):
    from datetime import datetime, timedelta
    from collections import defaultdict
    
    start_date = datetime.utcnow() - timedelta(days=30)
    events = db.query(models.Event).filter(models.Event.ts >= start_date).all()
    
    patterns = {
        "ssh_commands": defaultdict(int),
        "web_paths": defaultdict(int),
        "attack_times": defaultdict(int),
    }
    
    for e in events:
        if e.event_type == "ssh_connection":
            commands = e.payload.get("commands", [])
            for cmd in commands:
                if any(kw in cmd.lower() for kw in ["rm", "wget", "curl", "bash"]):
                    patterns["ssh_commands"][cmd[:50]] += 1
        elif e.event_type == "web_request":
            path = e.payload.get("path", "/")
            patterns["web_paths"][path] += 1
        
        hour = e.ts.hour
        patterns["attack_times"][f"{hour}:00"] += 1
    
    return {
        "dangerous_commands": dict(sorted(patterns["ssh_commands"].items(), key=lambda x: x[1], reverse=True)[:10]),
        "targeted_paths": dict(sorted(patterns["web_paths"].items(), key=lambda x: x[1], reverse=True)[:10]),
        "attack_hours": dict(patterns["attack_times"]),
    }





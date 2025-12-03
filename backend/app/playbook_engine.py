"""Playbook Automation Engine"""
from sqlalchemy.orm import Session
from . import models
import requests
import socket
import subprocess


def execute_playbook(playbook: models.Playbook, event: models.Event = None, ioc: models.IOC = None, db: Session = None):
    """Execute a playbook's steps"""
    if not playbook.enabled:
        return
    
    # Check trigger conditions
    if not _matches_trigger(playbook, event, ioc):
        return
    
    results = []
    for step in playbook.steps:
        try:
            result = _execute_step(step, event, ioc, db)
            results.append({"step": step, "result": result, "success": True})
        except Exception as e:
            results.append({"step": step, "result": str(e), "success": False})
    
    return results


def _matches_trigger(playbook: models.Playbook, event: models.Event = None, ioc: models.IOC = None) -> bool:
    """Check if playbook trigger conditions match"""
    conditions = playbook.trigger_conditions or {}
    
    if event:
        if conditions.get("event_type") and event.event_type != conditions["event_type"]:
            return False
        if conditions.get("min_score") and event.payload.get("score", 0) < conditions["min_score"]:
            return False
        return True
    
    if ioc:
        if conditions.get("min_score") and ioc.score < conditions["min_score"]:
            return False
        if conditions.get("ioc_type") and ioc.ioc_type != conditions["ioc_type"]:
            return False
        return True
    
    return False


def _execute_step(step: dict, event: models.Event = None, ioc: models.IOC = None, db: Session = None):
    """Execute a single playbook step"""
    action = step.get("action")
    target = step.get("target", "src_ip")
    
    # Get target value
    if event:
        value = getattr(event, target, event.payload.get(target, ""))
    elif ioc:
        value = ioc.value if target == "value" else getattr(ioc, target, "")
    else:
        value = ""
    
    if action == "whois":
        # Mock WHOIS lookup
        return {"action": "whois", "target": value, "result": "Mock WHOIS data"}
    
    elif action == "reverse_dns":
        try:
            hostname = socket.gethostbyaddr(value)[0]
            return {"action": "reverse_dns", "target": value, "result": hostname}
        except:
            return {"action": "reverse_dns", "target": value, "result": "N/A"}
    
    elif action == "shodan_lookup":
        # Mock Shodan lookup
        return {"action": "shodan_lookup", "target": value, "result": "Mock Shodan data"}
    
    elif action == "block_ip":
        from .routers_core import _block_ip_internal
        _block_ip_internal(value, f"Auto-blocked by playbook: {step.get('playbook_name', 'unknown')}", db)
        return {"action": "block_ip", "target": value, "result": "Blocked"}
    
    elif action == "webhook":
        url = step.get("webhook_url", "")
        payload = {"event": "playbook_triggered", "target": value, "step": step}
        try:
            requests.post(url, json=payload, timeout=5)
            return {"action": "webhook", "target": value, "result": "Sent"}
        except:
            return {"action": "webhook", "target": value, "result": "Failed"}
    
    elif action == "enrich_ioc":
        from .threat_intel import ThreatIntelligence
        ti = ThreatIntelligence()
        result = ti.enrich(ioc.ioc_type, ioc.value)
        return {"action": "enrich_ioc", "target": value, "result": result}
    
    return {"action": action, "target": value, "result": "Unknown action"}


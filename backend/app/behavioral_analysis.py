"""Behavioral Analysis Engine - Anomaly Detection and Pattern Recognition"""
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from . import models


def detect_brute_force(ip: str, db: Session, time_window_seconds: int = 300, min_attempts: int = 5) -> dict:
    """Detect brute force attacks"""
    start_time = datetime.utcnow() - timedelta(seconds=time_window_seconds)
    
    events = db.query(models.Event).filter(
        models.Event.src_ip == ip,
        models.Event.ts >= start_time,
        models.Event.event_type.in_(["ssh_connection", "login_attempt", "web_request"])
    ).all()
    
    # Count failed login attempts
    failed_attempts = [e for e in events if e.payload.get("success") == False]
    
    if len(failed_attempts) >= min_attempts:
        return {
            "detected": True,
            "type": "brute_force",
            "ip": ip,
            "attempts": len(failed_attempts),
            "time_window": time_window_seconds,
            "severity": "high" if len(failed_attempts) >= 10 else "medium",
        }
    
    return {"detected": False}


def detect_port_scan(ip: str, db: Session, time_window_seconds: int = 60, min_ports: int = 3) -> dict:
    """Detect port scanning activity"""
    start_time = datetime.utcnow() - timedelta(seconds=time_window_seconds)
    
    events = db.query(models.Event).filter(
        models.Event.src_ip == ip,
        models.Event.ts >= start_time
    ).all()
    
    # Count unique honeypots/ports
    honeypot_ids = set(e.honeypot_id for e in events)
    ports = set(e.dst_port for e in events)
    
    if len(honeypot_ids) >= min_ports or len(ports) >= min_ports:
        return {
            "detected": True,
            "type": "port_scan",
            "ip": ip,
            "honeypots_touched": len(honeypot_ids),
            "ports_scanned": len(ports),
            "time_window": time_window_seconds,
            "severity": "high" if len(honeypot_ids) >= 5 else "medium",
        }
    
    return {"detected": False}


def detect_credential_stuffing(ip: str, db: Session, time_window_seconds: int = 600) -> dict:
    """Detect credential stuffing attacks"""
    start_time = datetime.utcnow() - timedelta(seconds=time_window_seconds)
    
    events = db.query(models.Event).filter(
        models.Event.src_ip == ip,
        models.Event.ts >= start_time
    ).all()
    
    # Extract credentials
    credentials = []
    for e in events:
        if e.payload.get("username") and e.payload.get("password"):
            credentials.append((e.payload["username"], e.payload["password"]))
    
    # Count credential reuse across different honeypots
    credential_usage = defaultdict(set)
    for e in events:
        if e.payload.get("username") and e.payload.get("password"):
            cred = (e.payload["username"], e.payload["password"])
            credential_usage[cred].add(e.honeypot_id)
    
    # Check if same credentials used on multiple honeypots
    reused_creds = {cred: honeypots for cred, honeypots in credential_usage.items() if len(honeypots) >= 2}
    
    if reused_creds:
        return {
            "detected": True,
            "type": "credential_stuffing",
            "ip": ip,
            "reused_credentials": len(reused_creds),
            "honeypots_affected": len(set().union(*reused_creds.values())),
            "severity": "high",
        }
    
    return {"detected": False}


def detect_behavioral_anomaly(ip: str, db: Session) -> dict:
    """Detect behavioral anomalies"""
    # Get all events from this IP in last 24 hours
    start_time = datetime.utcnow() - timedelta(hours=24)
    events = db.query(models.Event).filter(
        models.Event.src_ip == ip,
        models.Event.ts >= start_time
    ).all()
    
    if not events:
        return {"detected": False}
    
    anomalies = []
    
    # Check for unusual time (attacks outside business hours)
    hours = [e.ts.hour for e in events]
    night_attacks = [h for h in hours if h < 6 or h > 22]
    if len(night_attacks) > len(hours) * 0.7:
        anomalies.append({
            "type": "unusual_time",
            "score": 0.7,
            "details": f"{len(night_attacks)}/{len(hours)} attacks during off-hours",
        })
    
    # Check for rapid scanning
    if len(events) > 10:
        time_span = (events[-1].ts - events[0].ts).total_seconds()
        if time_span < 300:  # 5 minutes
            anomalies.append({
                "type": "rapid_scan",
                "score": 0.8,
                "details": f"{len(events)} events in {time_span:.0f} seconds",
            })
    
    # Check for diverse attack techniques
    event_types = Counter(e.event_type for e in events)
    if len(event_types) >= 4:
        anomalies.append({
            "type": "diverse_techniques",
            "score": 0.6,
            "details": f"{len(event_types)} different attack types",
        })
    
    if anomalies:
        max_score = max(a["score"] for a in anomalies)
        return {
            "detected": True,
            "ip": ip,
            "anomalies": anomalies,
            "overall_score": max_score,
            "severity": "high" if max_score >= 0.7 else "medium",
        }
    
    return {"detected": False}


def analyze_attacker_behavior(ip: str, db: Session) -> dict:
    """Comprehensive behavioral analysis"""
    results = {
        "ip": ip,
        "brute_force": detect_brute_force(ip, db),
        "port_scan": detect_port_scan(ip, db),
        "credential_stuffing": detect_credential_stuffing(ip, db),
        "anomalies": detect_behavioral_anomaly(ip, db),
    }
    
    # Store behavioral anomaly if detected
    if results["anomalies"].get("detected"):
        anomaly = models.BehavioralAnomaly(
            ip=ip,
            anomaly_type="behavioral_analysis",
            score=results["anomalies"].get("overall_score", 0.0),
            details=results["anomalies"],
        )
        db.add(anomaly)
        db.commit()
    
    return results


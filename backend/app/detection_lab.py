"""Detection Lab - Pre-defined Attack Scenarios"""
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from . import models


DEFAULT_SCENARIOS = [
    {
        "name": "SSH Brute Force Attack",
        "description": "Detect multiple failed SSH login attempts from the same IP within a short time window",
        "scenario_type": "brute_force",
        "expected_patterns": {
            "event_type": "ssh_connection",
            "min_events": 5,
            "time_window_seconds": 300,
            "pattern": "multiple_login_attempts",
        },
        "hints": [
            "Look for multiple SSH connection events from the same IP",
            "Check for failed authentication attempts",
            "Time window should be less than 5 minutes",
        ],
    },
    {
        "name": "Port Scanning Activity",
        "description": "Detect rapid connection attempts to multiple ports or honeypots",
        "scenario_type": "port_scan",
        "expected_patterns": {
            "min_honeypots": 3,
            "time_window_seconds": 60,
            "pattern": "rapid_connections",
        },
        "hints": [
            "Check for connections to multiple honeypots",
            "Look for rapid sequential connections",
            "Time between connections should be very short",
        ],
    },
    {
        "name": "Credential Stuffing",
        "description": "Detect attempts to use known credential pairs across multiple services",
        "scenario_type": "credential_stuffing",
        "expected_patterns": {
            "min_services": 2,
            "same_credentials": True,
            "time_window_seconds": 600,
        },
        "hints": [
            "Look for same username/password across different honeypots",
            "Check web and SSH honeypots for credential reuse",
            "Time window can be up to 10 minutes",
        ],
    },
    {
        "name": "Web Path Enumeration",
        "description": "Detect systematic scanning of web paths (admin panels, APIs, etc.)",
        "scenario_type": "path_enumeration",
        "expected_patterns": {
            "event_type": "web_request",
            "min_paths": 10,
            "time_window_seconds": 300,
            "pattern": "systematic_scanning",
        },
        "hints": [
            "Look for multiple web requests to different paths",
            "Check for common admin paths (/admin, /wp-admin, etc.)",
            "Requests should be sequential and systematic",
        ],
    },
    {
        "name": "Data Exfiltration Attempt",
        "description": "Detect attempts to download or access sensitive files",
        "scenario_type": "data_exfiltration",
        "expected_patterns": {
            "event_type": "web_request",
            "sensitive_paths": [".git", ".env", "backup", "config"],
            "min_events": 3,
        },
        "hints": [
            "Look for requests to sensitive file paths",
            "Check for .git, .env, backup files",
            "Multiple attempts to access secrets",
        ],
    },
    {
        "name": "Multi-Stage Attack",
        "description": "Detect a coordinated attack across multiple honeypots with different techniques",
        "scenario_type": "multi_stage",
        "expected_patterns": {
            "min_honeypots": 2,
            "min_event_types": 3,
            "time_window_seconds": 1800,
            "pattern": "coordinated_attack",
        },
        "hints": [
            "Look for activity across multiple honeypots",
            "Different attack techniques (SSH, Web, Database)",
            "Time window can be up to 30 minutes",
        ],
    },
]


def seed_detection_lab_scenarios(db: Session):
    """Seed default detection lab scenarios"""
    existing = {s.name for s in db.query(models.DetectionLabScenario).all()}
    for scenario_data in DEFAULT_SCENARIOS:
        if scenario_data["name"] not in existing:
            scenario = models.DetectionLabScenario(
                name=scenario_data["name"],
                description=scenario_data["description"],
                scenario_type=scenario_data["scenario_type"],
                expected_patterns=scenario_data["expected_patterns"],
                hints=scenario_data["hints"],
            )
            db.add(scenario)
    db.commit()


def check_scenario(session_id: int, scenario_id: int, db: Session) -> dict:
    """Check if a session matches a detection lab scenario"""
    scenario = db.query(models.DetectionLabScenario).filter_by(id=scenario_id).first()
    if not scenario:
        return {"matched": False, "reason": "Scenario not found"}
    
    session = db.query(models.Session).filter_by(id=session_id).first()
    if not session:
        return {"matched": False, "reason": "Session not found"}
    
    # Get events for this session
    events = db.query(models.Event).filter_by(session_id=session_id).order_by(models.Event.ts.asc()).all()
    
    patterns = scenario.expected_patterns
    matched = False
    details = {}
    
    if scenario.scenario_type == "brute_force":
        # Check for multiple login attempts
        if patterns.get("event_type") == "ssh_connection":
            login_attempts = [e for e in events if e.event_type == "ssh_connection"]
            time_window = timedelta(seconds=patterns.get("time_window_seconds", 300))
            
            if len(login_attempts) >= patterns.get("min_events", 5):
                first_event = login_attempts[0].ts
                last_event = login_attempts[-1].ts
                if (last_event - first_event) <= time_window:
                    matched = True
                    details = {
                        "attempts": len(login_attempts),
                        "time_window": str(time_window),
                        "first_attempt": first_event.isoformat(),
                        "last_attempt": last_event.isoformat(),
                    }
    
    elif scenario.scenario_type == "port_scan":
        # Check for rapid connections to multiple honeypots
        honeypot_ids = set(e.honeypot_id for e in events)
        if len(honeypot_ids) >= patterns.get("min_honeypots", 3):
            time_window = timedelta(seconds=patterns.get("time_window_seconds", 60))
            first_event = events[0].ts
            last_event = events[-1].ts
            if (last_event - first_event) <= time_window:
                matched = True
                details = {
                    "honeypots_touched": len(honeypot_ids),
                    "time_window": str(time_window),
                    "events": len(events),
                }
    
    elif scenario.scenario_type == "path_enumeration":
        # Check for multiple web requests to different paths
        web_events = [e for e in events if e.event_type == "web_request"]
        paths = set(e.payload.get("path", "/") for e in web_events)
        if len(paths) >= patterns.get("min_paths", 10):
            matched = True
            details = {
                "unique_paths": len(paths),
                "total_requests": len(web_events),
                "paths": list(paths)[:10],
            }
    
    return {
        "matched": matched,
        "scenario_name": scenario.name,
        "details": details,
        "hints": scenario.hints,
    }


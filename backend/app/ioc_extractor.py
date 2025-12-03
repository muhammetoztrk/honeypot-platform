import re
from sqlalchemy.orm import Session
from datetime import datetime
from . import models


def extract_iocs(event: models.Event, db: Session):
    """Extract IOCs from event payload and store/update in IOC table"""
    payload = event.payload or {}
    src_ip = event.src_ip

    # Extract IP addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = set(re.findall(ip_pattern, str(payload)))
    if src_ip:
        ips.add(src_ip)

    for ip in ips:
        if ip != "0.0.0.0" and ip != "127.0.0.1":
            _upsert_ioc(db, "ip", ip, 10 if ip == src_ip else 5)

    # Extract URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, str(payload))
    for url in urls:
        _upsert_ioc(db, "url", url, 15)

    # Extract hashes (MD5, SHA1, SHA256)
    hash_patterns = {
        "md5": r'\b[a-fA-F0-9]{32}\b',
        "sha1": r'\b[a-fA-F0-9]{40}\b',
        "sha256": r'\b[a-fA-F0-9]{64}\b',
    }
    for hash_type, pattern in hash_patterns.items():
        hashes = re.findall(pattern, str(payload))
        for h in hashes:
            _upsert_ioc(db, "hash", h, 20)

    # Extract potential credentials (username:password patterns)
    cred_pattern = r'([a-zA-Z0-9_\-]+):([^\s:]+)'
    creds = re.findall(cred_pattern, str(payload))
    for username, password in creds:
        if len(username) > 2 and len(password) > 3:
            _upsert_ioc(db, "user", username, 25)
            _upsert_ioc(db, "pass", password, 30)


def _upsert_ioc(db: Session, ioc_type: str, value: str, base_score: int):
    """Create or update IOC entry"""
    existing = db.query(models.IOC).filter_by(ioc_type=ioc_type, value=value).first()
    if existing:
        existing.last_seen = datetime.utcnow()
        existing.seen_count += 1
        existing.score = min(existing.score + base_score, 100)  # Cap at 100
        # Check for alerts on high-risk IOC
        if existing.score >= 70 or existing.seen_count >= 5:
            from .alert_service import check_ioc_alerts
            check_ioc_alerts(existing, db)
            # Evaluate alert rules for IOC
            from .alert_rules_engine import evaluate_alert_rules
            evaluate_alert_rules(ioc=existing, db=db)
    else:
        ioc = models.IOC(
            ioc_type=ioc_type,
            value=value,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            seen_count=1,
            score=base_score,
        )
        db.add(ioc)
        db.flush()  # Flush to get ID
        # Evaluate alert rules for new IOC
        from .alert_rules_engine import evaluate_alert_rules
        evaluate_alert_rules(ioc=ioc, db=db)
        # Execute playbooks
        from .playbook_engine import execute_playbook
        from . import models
        playbooks = db.query(models.Playbook).filter_by(enabled=True).all()
        for playbook in playbooks:
            execute_playbook(playbook, ioc=ioc, db=db)


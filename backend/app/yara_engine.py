"""YARA Rule Engine"""
from sqlalchemy.orm import Session
from datetime import datetime
from . import models
import re


def match_yara_rules(content: str, db: Session) -> list:
    """Match content against YARA rules"""
    rules = db.query(models.YARARule).filter_by(enabled=True).all()
    matches = []
    
    for rule in rules:
        try:
            # Simple YARA-like pattern matching (simplified version)
            # In production, use actual YARA library
            matched_strings = []
            
            # Extract strings from YARA rule (simplified)
            string_patterns = re.findall(r'"(.*?)"', rule.rule_content)
            for pattern in string_patterns:
                if pattern in content:
                    matched_strings.append(pattern)
            
            if matched_strings:
                matches.append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "matched_strings": matched_strings,
                })
        except Exception:
            continue
    
    return matches


def check_event_yara(event: models.Event, db: Session):
    """Check event payload against YARA rules"""
    payload_str = str(event.payload)
    matches = match_yara_rules(payload_str, db)
    
    for match in matches:
        yara_match = models.YARAMatch(
            rule_id=match["rule_id"],
            event_id=event.id,
            matched_strings=match["matched_strings"],
        )
        db.add(yara_match)
    
    db.commit()
    return matches


def check_ioc_yara(ioc: models.IOC, db: Session):
    """Check IOC value against YARA rules"""
    matches = match_yara_rules(ioc.value, db)
    
    for match in matches:
        yara_match = models.YARAMatch(
            rule_id=match["rule_id"],
            ioc_id=ioc.id,
            matched_strings=match["matched_strings"],
        )
        db.add(yara_match)
    
    db.commit()
    return matches


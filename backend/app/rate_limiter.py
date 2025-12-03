"""Rate Limiting Engine"""
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from . import models
from collections import defaultdict


class RateLimiter:
    """Rate limiting tracker"""
    _counters = defaultdict(lambda: defaultdict(int))
    _windows = defaultdict(lambda: defaultdict(datetime))
    
    @classmethod
    def check_rate_limit(cls, rule: models.RateLimitRule, identifier: str) -> dict:
        """Check if identifier exceeds rate limit"""
        if not rule.enabled:
            return {"allowed": True}
        
        conditions = rule.conditions or {}
        max_requests = conditions.get("max_requests", 10)
        time_window = conditions.get("time_window", 60)  # seconds
        
        key = f"{rule.id}:{identifier}"
        now = datetime.utcnow()
        
        # Reset counter if window expired
        if key in cls._windows[rule.id] and (now - cls._windows[rule.id][key]).total_seconds() > time_window:
            cls._counters[rule.id][key] = 0
            cls._windows[rule.id][key] = now
        
        # Initialize if first request
        if key not in cls._windows[rule.id]:
            cls._windows[rule.id][key] = now
        
        # Check limit
        current_count = cls._counters[rule.id][key]
        
        if current_count >= max_requests:
            return {
                "allowed": False,
                "reason": f"Rate limit exceeded: {current_count}/{max_requests}",
                "action": rule.action,
            }
        
        # Increment counter
        cls._counters[rule.id][key] += 1
        
        return {"allowed": True, "count": current_count + 1, "limit": max_requests}
    
    @classmethod
    def check_ip_rate_limit(cls, ip: str, db: Session) -> dict:
        """Check rate limits for an IP address"""
        rules = db.query(models.RateLimitRule).filter_by(
            enabled=True,
            rule_type="ip"
        ).all()
        
        results = []
        blocked = False
        
        for rule in rules:
            result = cls.check_rate_limit(rule, ip)
            results.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "result": result,
            })
            
            if not result.get("allowed", True) and rule.action == "block":
                blocked = True
        
        return {
            "blocked": blocked,
            "results": results,
        }


"""Advanced Analytics Engine"""
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from . import models


def get_attack_correlation(ip: str, db: Session, hours: int = 24) -> dict:
    """Correlate events to identify attack patterns"""
    start_time = datetime.utcnow() - timedelta(hours=hours)
    events = db.query(models.Event).filter(
        models.Event.src_ip == ip,
        models.Event.ts >= start_time
    ).order_by(models.Event.ts.asc()).all()
    
    correlations = {
        "honeypot_sequence": [],
        "event_type_sequence": [],
        "time_patterns": {},
    }
    
    if events:
        # Honeypot sequence
        honeypot_sequence = [e.honeypot_id for e in events]
        correlations["honeypot_sequence"] = honeypot_sequence
        
        # Event type sequence
        event_sequence = [e.event_type for e in events]
        correlations["event_type_sequence"] = event_sequence
        
        # Time patterns
        hours_activity = Counter(e.ts.hour for e in events)
        correlations["time_patterns"] = {
            "peak_hours": dict(hours_activity.most_common(3)),
            "total_hours_active": len(hours_activity),
        }
    
    return correlations


def generate_attack_heatmap(db: Session, days: int = 7) -> dict:
    """Generate attack heatmap data"""
    start_time = datetime.utcnow() - timedelta(days=days)
    events = db.query(models.Event).filter(models.Event.ts >= start_time).all()
    
    heatmap = defaultdict(lambda: defaultdict(int))
    
    for event in events:
        hour = event.ts.hour
        day = event.ts.weekday()  # 0 = Monday, 6 = Sunday
        heatmap[day][hour] += 1
    
    return {
        "data": dict(heatmap),
        "total_events": len(events),
        "days": days,
    }


def calculate_attack_trends(db: Session, days: int = 30) -> dict:
    """Calculate attack trends over time"""
    start_time = datetime.utcnow() - timedelta(days=days)
    events = db.query(models.Event).filter(models.Event.ts >= start_time).all()
    
    # Group by day
    daily_events = defaultdict(int)
    daily_by_type = defaultdict(lambda: defaultdict(int))
    
    for event in events:
        day = event.ts.date()
        daily_events[day.isoformat()] += 1
        daily_by_type[day.isoformat()][event.event_type] += 1
    
    # Calculate trends
    days_list = sorted(daily_events.keys())
    if len(days_list) >= 2:
        recent_avg = sum(daily_events[d] for d in days_list[-7:]) / 7
        previous_avg = sum(daily_events[d] for d in days_list[-14:-7]) / 7 if len(days_list) >= 14 else recent_avg
        trend = "increasing" if recent_avg > previous_avg * 1.1 else "decreasing" if recent_avg < previous_avg * 0.9 else "stable"
    else:
        trend = "stable"
    
    return {
        "daily_events": dict(daily_events),
        "daily_by_type": {k: dict(v) for k, v in daily_by_type.items()},
        "trend": trend,
        "total_events": len(events),
    }


def get_top_attack_patterns(db: Session, limit: int = 10) -> list:
    """Get top attack patterns"""
    events = db.query(models.Event).filter(
        models.Event.ts >= datetime.utcnow() - timedelta(days=30)
    ).all()
    
    # Group by IP and event sequence
    patterns = defaultdict(int)
    
    ip_events = defaultdict(list)
    for event in events:
        ip_events[event.src_ip].append(event.event_type)
    
    for ip, event_types in ip_events.items():
        if len(event_types) >= 2:
            pattern = " -> ".join(event_types[:5])  # First 5 events
            patterns[pattern] += 1
    
    top_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    return [
        {"pattern": pattern, "count": count, "percentage": (count / len(events)) * 100}
        for pattern, count in top_patterns
    ]


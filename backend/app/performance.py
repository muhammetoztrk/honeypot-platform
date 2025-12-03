"""Performance Optimization - Caching, indexing, async processing"""
from functools import lru_cache
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import Index, event
from . import models
import hashlib
import json


# In-memory cache for frequently accessed data
_cache: Dict[str, tuple] = {}  # key -> (value, expiry_time)


def cache_get(key: str, ttl_seconds: int = 300) -> Optional[Any]:
    """Get value from cache"""
    if key in _cache:
        value, expiry = _cache[key]
        if datetime.utcnow() < expiry:
            return value
        else:
            del _cache[key]
    return None


def cache_set(key: str, value: Any, ttl_seconds: int = 300):
    """Set value in cache"""
    expiry = datetime.utcnow() + timedelta(seconds=ttl_seconds)
    _cache[key] = (value, expiry)


def cache_clear(pattern: Optional[str] = None):
    """Clear cache entries"""
    if pattern:
        keys_to_delete = [k for k in _cache.keys() if pattern in k]
        for k in keys_to_delete:
            del _cache[k]
    else:
        _cache.clear()


@lru_cache(maxsize=1000)
def get_cached_node(api_key: str) -> Optional[Dict[str, Any]]:
    """Get cached node by API key (LRU cache)"""
    # This will be called from router with actual DB query
    return None


def get_cached_metrics(db: Session) -> Dict[str, Any]:
    """Get cached system metrics"""
    cache_key = "system_metrics"
    cached = cache_get(cache_key, ttl_seconds=60)  # 1 minute cache
    
    if cached:
        return cached
    
    from .monitoring import MetricsCollector
    metrics = MetricsCollector.get_metrics(db)
    cache_set(cache_key, metrics, ttl_seconds=60)
    return metrics


def get_cached_dashboard_data(db: Session) -> Dict[str, Any]:
    """Get cached dashboard data"""
    cache_key = "dashboard_data"
    cached = cache_get(cache_key, ttl_seconds=30)  # 30 second cache
    
    if cached:
        return cached
    
    from datetime import datetime, timedelta
    last_24h = datetime.utcnow() - timedelta(hours=24)
    
    data = {
        "nodes": db.query(models.Node).count(),
        "honeypots": db.query(models.Honeypot).count(),
        "sessions": db.query(models.Session).filter(models.Session.started_at >= last_24h).count(),
        "iocs": db.query(models.IOC).count(),
        "alerts": db.query(models.Alert).filter_by(read=False).count(),
    }
    
    cache_set(cache_key, data, ttl_seconds=30)
    return data


def create_database_indexes():
    """Create database indexes for performance"""
    from sqlalchemy import inspect
    indexes = [
        # Event indexes
        Index('idx_event_src_ip', models.Event.src_ip),
        Index('idx_event_ts', models.Event.ts),
        Index('idx_event_type', models.Event.event_type),
        Index('idx_event_honeypot_id', models.Event.honeypot_id),
        
        # IOC indexes (only create if not already exists - model has index=True on value)
        Index('idx_ioc_type', models.IOC.ioc_type),
        Index('idx_ioc_score', models.IOC.score),
        
        # Session indexes
        Index('idx_session_src_ip', models.Session.src_ip),
        Index('idx_session_started_at', models.Session.started_at),
        
        # Alert indexes
        Index('idx_alert_read', models.Alert.read),
        Index('idx_alert_severity', models.Alert.severity),
        
        # Node indexes (only create if not already exists - model has index=True on api_key)
        Index('idx_node_last_heartbeat', models.Node.last_heartbeat_at),
    ]
    return indexes


def optimize_query(query, limit: int = 1000):
    """Optimize query with pagination"""
    return query.limit(limit)


def batch_process(items: list, batch_size: int = 100, processor=None):
    """Process items in batches"""
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        if processor:
            processor(batch)
        yield batch


"""Production Monitoring - Health checks, metrics, structured logging"""
import time
import logging
from datetime import datetime
from typing import Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import text
from . import models
import psutil
import os


# Structured logging setup
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "module": "%(name)s", "message": "%(message)s"}',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class HealthChecker:
    """System health checker"""
    
    @staticmethod
    def check_database(db: Session) -> Dict[str, Any]:
        """Check database connectivity and performance"""
        try:
            start = time.time()
            db.execute(text("SELECT 1"))
            db.commit()
            response_time = (time.time() - start) * 1000
            
            # Check table counts
            node_count = db.query(models.Node).count()
            honeypot_count = db.query(models.Honeypot).count()
            event_count = db.query(models.Event).count()
            
            return {
                "status": "healthy",
                "response_time_ms": round(response_time, 2),
                "node_count": node_count,
                "honeypot_count": honeypot_count,
                "event_count": event_count,
            }
        except Exception as e:
            logger.error(f"Database health check failed: {str(e)}", extra={"error": str(e)})
            return {
                "status": "unhealthy",
                "error": str(e),
            }
    
    @staticmethod
    def check_system_resources() -> Dict[str, Any]:
        """Check system resource usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                "status": "healthy",
                "cpu_percent": cpu_percent,
                "memory": {
                    "total_gb": round(memory.total / (1024**3), 2),
                    "used_gb": round(memory.used / (1024**3), 2),
                    "percent": memory.percent,
                },
                "disk": {
                    "total_gb": round(disk.total / (1024**3), 2),
                    "used_gb": round(disk.used / (1024**3), 2),
                    "percent": round((disk.used / disk.total) * 100, 2),
                },
            }
        except Exception as e:
            logger.error(f"System resource check failed: {str(e)}", extra={"error": str(e)})
            return {
                "status": "unhealthy",
                "error": str(e),
            }
    
    @staticmethod
    def check_honeypot_services(db: Session) -> Dict[str, Any]:
        """Check honeypot service status"""
        try:
            from .honeypot_services import HoneypotManager
            
            all_honeypots = db.query(models.Honeypot).all()
            running_count = 0
            stopped_count = 0
            
            for hp in all_honeypots:
                if HoneypotManager.is_running(hp.id):
                    running_count += 1
                else:
                    stopped_count += 1
            
            return {
                "status": "healthy" if stopped_count == 0 else "degraded",
                "running": running_count,
                "stopped": stopped_count,
                "total": len(all_honeypots),
            }
        except Exception as e:
            logger.error(f"Honeypot service check failed: {str(e)}", extra={"error": str(e)})
            return {
                "status": "unhealthy",
                "error": str(e),
            }
    
    @staticmethod
    def full_health_check(db: Session) -> Dict[str, Any]:
        """Perform full system health check"""
        db_health = HealthChecker.check_database(db)
        system_health = HealthChecker.check_system_resources()
        honeypot_health = HealthChecker.check_honeypot_services(db)
        
        overall_status = "healthy"
        if db_health.get("status") != "healthy":
            overall_status = "unhealthy"
        elif system_health.get("status") != "healthy":
            overall_status = "unhealthy"
        elif honeypot_health.get("status") == "unhealthy":
            overall_status = "unhealthy"
        elif honeypot_health.get("status") == "degraded":
            overall_status = "degraded"
        
        return {
            "status": overall_status,
            "timestamp": datetime.utcnow().isoformat(),
            "database": db_health,
            "system": system_health,
            "honeypots": honeypot_health,
        }


class MetricsCollector:
    """Collect system metrics"""
    
    @staticmethod
    def get_metrics(db: Session) -> Dict[str, Any]:
        """Collect all system metrics"""
        from datetime import datetime, timedelta
        
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        
        # Event metrics
        total_events = db.query(models.Event).count()
        events_24h = db.query(models.Event).filter(models.Event.ts >= last_24h).count()
        events_7d = db.query(models.Event).filter(models.Event.ts >= last_7d).count()
        
        # IOC metrics
        total_iocs = db.query(models.IOC).count()
        high_risk_iocs = db.query(models.IOC).filter(models.IOC.risk_score >= 70).count()
        
        # Alert metrics
        total_alerts = db.query(models.Alert).count()
        unread_alerts = db.query(models.Alert).filter_by(status="unread").count()
        
        # Honeypot metrics
        total_honeypots = db.query(models.Honeypot).count()
        active_honeypots = db.query(models.Honeypot).count()
        
        # Node metrics
        total_nodes = db.query(models.Node).count()
        online_nodes = db.query(models.Node).filter(
            models.Node.last_heartbeat_at >= now - timedelta(minutes=5)
        ).count()
        
        return {
            "timestamp": now.isoformat(),
            "events": {
                "total": total_events,
                "last_24h": events_24h,
                "last_7d": events_7d,
            },
            "iocs": {
                "total": total_iocs,
                "high_risk": high_risk_iocs,
            },
            "alerts": {
                "total": total_alerts,
                "unread": unread_alerts,
            },
            "honeypots": {
                "total": total_honeypots,
                "active": active_honeypots,
            },
            "nodes": {
                "total": total_nodes,
                "online": online_nodes,
            },
        }


def log_event(level: str, message: str, **kwargs):
    """Structured logging helper"""
    if kwargs:
        message = f"{message} | {', '.join(f'{k}={v}' for k, v in kwargs.items())}"
    if level == "info":
        logger.info(message)
    elif level == "warning":
        logger.warning(message)
    elif level == "error":
        logger.error(message)
    elif level == "critical":
        logger.critical(message)


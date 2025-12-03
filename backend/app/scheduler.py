"""Scheduled Reports Scheduler"""
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from .database import SessionLocal
from . import models
from .pdf_report import generate_pdf_report
from .email_service import send_alert_email
import requests


scheduler = BackgroundScheduler()


def run_scheduled_reports():
    """Check and run scheduled reports"""
    from .database import SessionLocal
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        reports = db.query(models.ScheduledReport).filter_by(enabled=True).filter(
            models.ScheduledReport.next_run <= now
        ).all()
        
        for report in reports:
            try:
                # Generate report
                events = db.query(models.Event).order_by(models.Event.ts.desc()).limit(1000).all()
                iocs = db.query(models.IOC).order_by(models.IOC.score.desc()).limit(100).all()
                
                stats = {
                    "nodes": db.query(models.Node).count(),
                    "honeypots": db.query(models.Honeypot).filter_by(status="running").count(),
                    "events": len(events),
                    "iocs": len(iocs),
                }
                
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
                
                if report.format == "pdf":
                    pdf_buffer = generate_pdf_report(events_data, iocs_data, stats)
                    # In production, save to file and attach to email
                    # For now, just send notification
                    for recipient in report.recipients:
                        try:
                            send_alert_email(
                                to_email=recipient,
                                subject=f"Scheduled Report: {report.name}",
                                message=f"Your scheduled report '{report.name}' has been generated."
                            )
                        except Exception:
                            pass
                
                # Update next run time
                if report.schedule_type == "daily":
                    report.next_run = now + timedelta(days=1)
                elif report.schedule_type == "weekly":
                    report.next_run = now + timedelta(weeks=1)
                elif report.schedule_type == "monthly":
                    report.next_run = now + timedelta(days=30)
                
                report.last_run = now
                db.commit()
            except Exception as e:
                print(f"Error running scheduled report {report.id}: {e}")
    finally:
        db.close()


def start_scheduler():
    """Start the scheduler"""
    scheduler.add_job(
        run_scheduled_reports,
        trigger=CronTrigger(minute="*/5"),  # Run every 5 minutes
        id="scheduled_reports",
        replace_existing=True,
    )
    scheduler.start()


def stop_scheduler():
    """Stop the scheduler"""
    scheduler.shutdown()


from datetime import datetime
from typing import Optional

from sqlalchemy import String, Integer, DateTime, ForeignKey, JSON, Text, Table, Column
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="admin")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Node(Base):
    __tablename__ = "nodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    api_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    organization_id: Mapped[Optional[int]] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    last_heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    honeypots: Mapped[list["Honeypot"]] = relationship(back_populates="node")


class HoneypotTemplate(Base):
    __tablename__ = "honeypot_templates"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    type: Mapped[str] = mapped_column(String(32))  # ssh/web/db/ics
    default_config: Mapped[dict] = mapped_column(JSON, default=dict)


class Honeypot(Base):
    __tablename__ = "honeypots"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"))
    template_id: Mapped[int] = mapped_column(ForeignKey("honeypot_templates.id"))
    campaign_id: Mapped[Optional[int]] = mapped_column(ForeignKey("campaigns.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(100))
    listen_ip: Mapped[str] = mapped_column(String(64), default="0.0.0.0")
    listen_port: Mapped[int] = mapped_column(Integer, default=22)
    status: Mapped[str] = mapped_column(String(32), default="stopped")
    config: Mapped[dict] = mapped_column(JSON, default=dict)

    node: Mapped[Node] = relationship(back_populates="honeypots")
    template: Mapped[HoneypotTemplate] = relationship()


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    honeypot_id: Mapped[int] = mapped_column(ForeignKey("honeypots.id"))
    src_ip: Mapped[str] = mapped_column(String(64))
    src_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(16))
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    score: Mapped[int] = mapped_column(Integer, default=0)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"))
    honeypot_id: Mapped[int] = mapped_column(ForeignKey("honeypots.id"))
    campaign_id: Mapped[Optional[int]] = mapped_column(ForeignKey("campaigns.id"), nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    src_ip: Mapped[str] = mapped_column(String(64))
    dst_port: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON)


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(primary_key=True)
    ioc_type: Mapped[str] = mapped_column(String(32))  # ip/url/hash/user/pass
    value: Mapped[str] = mapped_column(Text, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    seen_count: Mapped[int] = mapped_column(Integer, default=1)
    score: Mapped[int] = mapped_column(Integer, default=0)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    severity: Mapped[str] = mapped_column(String(32))  # low/medium/high/critical
    title: Mapped[str] = mapped_column(String(255))
    message: Mapped[str] = mapped_column(Text)
    event_id: Mapped[Optional[int]] = mapped_column(ForeignKey("events.id"), nullable=True)
    ioc_id: Mapped[Optional[int]] = mapped_column(ForeignKey("iocs.id"), nullable=True)
    read: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    reason: Mapped[str] = mapped_column(String(255))
    blocked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    blocked_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)


class IOCEnrichment(Base):
    __tablename__ = "ioc_enrichments"

    id: Mapped[int] = mapped_column(primary_key=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id"))
    source: Mapped[str] = mapped_column(String(64))  # virustotal, abuseipdb, etc
    data: Mapped[dict] = mapped_column(JSON)
    enriched_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(default=True)
    conditions: Mapped[dict] = mapped_column(JSON)  # {min_score: 70, min_seen_count: 5, event_type: "ssh_connection"}
    actions: Mapped[dict] = mapped_column(JSON)  # {block_ip: true, send_email: true, webhook_url: "..."}
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ScheduledReport(Base):
    __tablename__ = "scheduled_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(default=True)
    schedule_type: Mapped[str] = mapped_column(String(32))  # daily, weekly, monthly
    format: Mapped[str] = mapped_column(String(16), default="pdf")  # pdf, html, json
    recipients: Mapped[list] = mapped_column(JSON, default=list)  # ["email1@example.com", "email2@example.com"]
    last_run: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    next_run: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class WebhookConfig(Base):
    __tablename__ = "webhook_configs"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(Text)
    type: Mapped[str] = mapped_column(String(32))  # slack, discord, generic
    enabled: Mapped[bool] = mapped_column(default=True)
    events: Mapped[list] = mapped_column(JSON, default=list)  # ["high_risk_ioc", "ip_blocked", "alert_created"]
    secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Backup(Base):
    __tablename__ = "backups"

    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(Integer)
    backup_type: Mapped[str] = mapped_column(String(32))  # full, events, iocs
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class UserOrganization(Base):
    __tablename__ = "user_organizations"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    role: Mapped[str] = mapped_column(String(32), default="member")  # admin, member, viewer


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open")  # open, investigating, contained, closed
    severity: Mapped[str] = mapped_column(String(32), default="medium")  # low, medium, high, critical
    assigned_to: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    organization_id: Mapped[Optional[int]] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"))


class IncidentIOC(Base):
    __tablename__ = "incident_iocs"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id"))


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    color: Mapped[str] = mapped_column(String(16), default="#22c55e")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class EventTag(Base):
    __tablename__ = "event_tags"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"))
    tag_id: Mapped[int] = mapped_column(ForeignKey("tags.id"))


class IOCTag(Base):
    __tablename__ = "ioc_tags"

    id: Mapped[int] = mapped_column(primary_key=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id"))
    tag_id: Mapped[int] = mapped_column(ForeignKey("tags.id"))


class HoneypotTag(Base):
    __tablename__ = "honeypot_tags"

    id: Mapped[int] = mapped_column(primary_key=True)
    honeypot_id: Mapped[int] = mapped_column(ForeignKey("honeypots.id"))
    tag_id: Mapped[int] = mapped_column(ForeignKey("tags.id"))


class MITREMapping(Base):
    __tablename__ = "mitre_mappings"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    technique_id: Mapped[str] = mapped_column(String(32))  # T1059, T1190, etc
    technique_name: Mapped[str] = mapped_column(String(255))
    tactic: Mapped[str] = mapped_column(String(64))  # Initial Access, Execution, etc


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    trigger_conditions: Mapped[dict] = mapped_column(JSON)  # {event_type: "ssh_connection", min_score: 70}
    steps: Mapped[list] = mapped_column(JSON)  # [{action: "whois", target: "src_ip"}, {action: "block_ip"}]
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ShareLink(Base):
    __tablename__ = "share_links"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    resource_type: Mapped[str] = mapped_column(String(32))  # dashboard, report, incident
    resource_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ArchiveRule(Base):
    __tablename__ = "archive_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(default=True)
    resource_type: Mapped[str] = mapped_column(String(32))  # events, iocs, sessions
    retention_days: Mapped[int] = mapped_column(Integer, default=90)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AttackerProfile(Base):
    __tablename__ = "attacker_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)  # 0-100
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    total_events: Mapped[int] = mapped_column(Integer, default=0)
    honeypots_touched: Mapped[int] = mapped_column(Integer, default=0)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    countries: Mapped[list] = mapped_column(JSON, default=list)
    profile_data: Mapped[dict] = mapped_column(JSON, default=dict)  # ASN, ISP, etc. (renamed from metadata)


class AlertAggregation(Base):
    __tablename__ = "alert_aggregations"

    id: Mapped[int] = mapped_column(primary_key=True)
    pattern_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # Hash of IP + event_type + path
    ip: Mapped[str] = mapped_column(String(64))
    event_type: Mapped[str] = mapped_column(String(64))
    count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    alert_id: Mapped[Optional[int]] = mapped_column(ForeignKey("alerts.id"), nullable=True)


class SuppressRule(Base):
    __tablename__ = "suppress_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(default=True)
    conditions: Mapped[dict] = mapped_column(JSON)  # {ip: "1.2.3.4", event_type: "ssh_connection", duration_hours: 24}
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="draft")  # draft, active, paused, completed
    target_network: Mapped[str] = mapped_column(String(255), nullable=True)  # DMZ, internal, external
    organization_id: Mapped[Optional[int]] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CampaignHoneypot(Base):
    __tablename__ = "campaign_honeypots"

    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"))
    honeypot_id: Mapped[int] = mapped_column(ForeignKey("honeypots.id"))


class CampaignEvent(Base):
    __tablename__ = "campaign_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"))
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"))


class DetectionLabScenario(Base):
    __tablename__ = "detection_lab_scenarios"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    scenario_type: Mapped[str] = mapped_column(String(64))  # brute_force, port_scan, credential_stuffing, etc.
    expected_patterns: Mapped[dict] = mapped_column(JSON)  # {event_count: 10, time_window: 300, etc.}
    hints: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AttackPattern(Base):
    __tablename__ = "attack_patterns"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    pattern_type: Mapped[str] = mapped_column(String(64))  # brute_force, port_scan, credential_stuffing, etc.
    conditions: Mapped[dict] = mapped_column(JSON)  # {min_events: 5, time_window: 60, etc.}
    severity: Mapped[str] = mapped_column(String(32), default="medium")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class BehavioralAnomaly(Base):
    __tablename__ = "behavioral_anomalies"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64))
    anomaly_type: Mapped[str] = mapped_column(String(64))  # unusual_time, rapid_scan, etc.
    score: Mapped[float] = mapped_column(default=0.0)
    details: Mapped[dict] = mapped_column(JSON)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AttackChain(Base):
    __tablename__ = "attack_chains"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    stages: Mapped[list] = mapped_column(JSON)  # List of attack stages
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    status: Mapped[str] = mapped_column(String(32), default="active")  # active, contained, closed


class ThreatIntelFeed(Base):
    __tablename__ = "threat_intel_feeds"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(64))  # abuseipdb, virustotal, otx, misp
    api_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    last_sync: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class HoneypotHealth(Base):
    __tablename__ = "honeypot_health"

    id: Mapped[int] = mapped_column(primary_key=True)
    honeypot_id: Mapped[int] = mapped_column(ForeignKey("honeypots.id"))
    status: Mapped[str] = mapped_column(String(32))  # healthy, degraded, down
    response_time_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    uptime_percent: Mapped[float] = mapped_column(default=100.0)
    last_check: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)


class GeoBlockRule(Base):
    __tablename__ = "geo_block_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(32))  # block, allow, alert
    countries: Mapped[list] = mapped_column(JSON, default=list)  # List of country codes
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TimeBasedRule(Base):
    __tablename__ = "time_based_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(32))  # block, allow, alert
    time_window: Mapped[dict] = mapped_column(JSON)  # {start_hour: 0, end_hour: 6, days: [0,1,2,3,4,5,6]}
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class SIEMIntegration(Base):
    __tablename__ = "siem_integrations"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    siem_type: Mapped[str] = mapped_column(String(64))  # splunk, qradar, arcsight, logrhythm
    endpoint: Mapped[str] = mapped_column(Text)
    api_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ComplianceReport(Base):
    __tablename__ = "compliance_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    compliance_type: Mapped[str] = mapped_column(String(64))  # gdpr, hipaa, pci_dss, iso27001
    report_data: Mapped[dict] = mapped_column(JSON)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)


class CustomDashboard(Base):
    __tablename__ = "custom_dashboards"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    layout: Mapped[dict] = mapped_column(JSON)  # Dashboard widget layout
    widgets: Mapped[list] = mapped_column(JSON, default=list)  # List of widgets
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    attribution_score: Mapped[float] = mapped_column(default=0.0)
    techniques: Mapped[list] = mapped_column(JSON, default=list)  # MITRE techniques
    iocs: Mapped[list] = mapped_column(JSON, default=list)  # Associated IOCs
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class YARARule(Base):
    __tablename__ = "yara_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    rule_content: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class YARAMatch(Base):
    __tablename__ = "yara_matches"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("yara_rules.id"))
    event_id: Mapped[Optional[int]] = mapped_column(ForeignKey("events.id"), nullable=True)
    ioc_id: Mapped[Optional[int]] = mapped_column(ForeignKey("iocs.id"), nullable=True)
    matched_strings: Mapped[list] = mapped_column(JSON, default=list)
    matched_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class RateLimitRule(Base):
    __tablename__ = "rate_limit_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    rule_type: Mapped[str] = mapped_column(String(32))  # ip, event_type, honeypot
    conditions: Mapped[dict] = mapped_column(JSON)  # {max_requests: 10, time_window: 60}
    action: Mapped[str] = mapped_column(String(32))  # block, alert, throttle
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class IPReputation(Base):
    __tablename__ = "ip_reputations"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    reputation_score: Mapped[int] = mapped_column(Integer, default=50)  # 0-100
    sources: Mapped[list] = mapped_column(JSON, default=list)  # Reputation sources
    last_updated: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Honeytoken(Base):
    __tablename__ = "honeytokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    token_type: Mapped[str] = mapped_column(String(32))  # credential, api_key, file, url
    token_value: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="active")  # active, triggered, expired
    triggered_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(Text)
    events: Mapped[list] = mapped_column(JSON, default=list)  # Events to trigger webhook
    secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class DataRetentionPolicy(Base):
    __tablename__ = "data_retention_policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    resource_type: Mapped[str] = mapped_column(String(32))  # events, iocs, sessions
    retention_days: Mapped[int] = mapped_column(Integer)
    archive_before_delete: Mapped[bool] = mapped_column(default=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(64))  # create, update, delete, login, etc.
    resource_type: Mapped[str] = mapped_column(String(32))  # honeypot, node, user, etc.
    resource_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)




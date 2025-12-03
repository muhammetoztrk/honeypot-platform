from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time
import logging

from .database import Base, engine, get_db
from . import models  # noqa: F401
from .routers_auth import router as auth_router
from .routers_core import router as core_router
from .routers_advanced import router as advanced_router
from .routers_setup import router as setup_router
from .monitoring import HealthChecker, log_event
from .performance import cache_clear


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Create tables and seed default data
    Base.metadata.create_all(bind=engine)
    
    # Create database indexes for performance
    try:
        from .performance import create_database_indexes
        indexes = create_database_indexes()
        # Note: Indexes should be created via migrations in production
        log_event("info", "Database indexes prepared", indexes_count=len(indexes))
    except Exception as e:
        log_event("warning", "Failed to prepare indexes", error=str(e))
    
    db = next(get_db())
    try:
        # Ensure default honeypot templates exist (idempotent)
        default_templates = [
            # Core templates
            ("SSH Honeypot", "ssh", {"banner": "SSH-2.0-OpenSSH_7.4"}),
            ("Web Honeypot", "web", {"server": "nginx/1.18.0"}),
            ("Database Honeypot", "db", {"version": "MySQL 5.7.0"}),
            ("ICS Honeypot", "ics", {"protocol": "Modbus"}),
            # Extended templates
            ("WordPress Honeypot", "web", {"server": "nginx/1.18.0", "paths": ["/wp-login.php", "/wp-admin", "/xmlrpc.php"]}),
            ("phpMyAdmin Honeypot", "web", {"server": "nginx/1.18.0", "paths": ["/phpmyadmin", "/pma"]}),
            ("E-commerce Login", "web", {"server": "nginx/1.18.0", "paths": ["/login", "/cart", "/checkout"]}),
            ("Linux Production Server", "ssh", {"banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "os": "Ubuntu 20.04 LTS"}),
            ("Network Appliance", "ssh", {"banner": "Cisco IOS Software", "commands": ["show run", "show ip int brief"]}),
            ("Legacy MySQL 5.x", "db", {"version": "MySQL 5.5.62", "charset": "utf8"}),
            ("PostgreSQL App DB", "db", {"version": "PostgreSQL 12.8", "database": "app_prod"}),
            ("Modbus PLC", "ics", {"protocol": "Modbus TCP", "unit_id": 1}),
            ("DNP3 Substation", "ics", {"protocol": "DNP3", "station": "SUB001"}),
            ("Fake REST API", "web", {"server": "nginx/1.18.0", "paths": ["/api/v1/login", "/api/v1/admin/users"]}),
            ("Kubernetes Dashboard", "web", {"server": "nginx/1.18.0", "paths": ["/k8s/dashboard", "/kubernetes"]}),
            ("Jenkins CI", "web", {"server": "nginx/1.18.0", "paths": ["/jenkins", "/ci"]}),
            # Faz 1: New Advanced Templates
            ("Open Relay Mail Server", "smtp", {"banner": "220 mail.example.com ESMTP Postfix", "relay": True}),
            ("Corporate Mail Gateway", "smtp", {"banner": "220 mail.corporate.com Microsoft ESMTP", "domain": "corporate.com"}),
            ("Home Router Panel", "web", {"server": "nginx/1.18.0", "paths": ["/admin", "/router", "/login"], "brand": "TP-Link"}),
            ("IoT Hub Admin", "web", {"server": "nginx/1.18.0", "paths": ["/hub", "/iot", "/admin"], "brand": "SmartHome"}),
            ("Fake SSO / Okta", "web", {"server": "nginx/1.18.0", "paths": ["/sso", "/okta", "/login"], "sso_provider": "Okta"}),
            ("Fake Office365 Login", "web", {"server": "nginx/1.18.0", "paths": ["/login", "/office365", "/microsoft"], "sso_provider": "Microsoft"}),
            ("Git Secrets Honeypot", "web", {"server": "nginx/1.18.0", "paths": ["/.git", "/.git/config", "/backup.zip", "/config", "/.env"], "secrets": True}),
            # Network & Protocol Honeypots
            ("FTP Server", "ftp", {"banner": "220 FTP Server Ready", "port": 21}),
            ("Telnet Server", "telnet", {"banner": "Welcome to Telnet Server", "port": 23}),
            ("RDP Server", "rdp", {"version": "RDP 10.0", "port": 3389}),
            ("VNC Server", "vnc", {"version": "RFB 003.008", "port": 5900}),
            ("SMB/CIFS Share", "smb", {"version": "SMB 2.1", "port": 445}),
            ("SNMP Agent", "snmp", {"version": "SNMPv2", "port": 161}),
            ("LDAP Directory", "ldap", {"version": "LDAPv3", "port": 389}),
            ("NTP Server", "ntp", {"version": "NTPv4", "port": 123}),
            ("DNS Server", "dns", {"version": "BIND 9.16", "port": 53}),
            ("SIP Proxy", "sip", {"version": "SIP/2.0", "port": 5060}),
            # Database Honeypots
            ("Redis Server", "redis", {"version": "Redis 6.2", "port": 6379}),
            ("MongoDB Server", "mongodb", {"version": "MongoDB 5.0", "port": 27017}),
            ("Elasticsearch Node", "elasticsearch", {"version": "Elasticsearch 7.15", "port": 9200}),
            ("Cassandra Node", "cassandra", {"version": "Cassandra 4.0", "port": 9042}),
            ("InfluxDB Server", "influxdb", {"version": "InfluxDB 2.0", "port": 8086}),
            # Cloud & Container Honeypots
            ("Docker API", "docker", {"version": "Docker 20.10", "port": 2375}),
            ("Kubernetes API", "k8s", {"version": "Kubernetes v1.22", "port": 6443}),
            ("AWS S3 Bucket", "s3", {"region": "us-east-1", "bucket": "fake-bucket"}),
            ("Azure Blob Storage", "azure", {"account": "fakeaccount", "container": "fakecontainer"}),
            ("GCP Cloud Storage", "gcp", {"bucket": "fake-bucket", "project": "fake-project"}),
            # IoT & SCADA Honeypots
            ("MQTT Broker", "mqtt", {"version": "MQTT 3.1.1", "port": 1883}),
            ("CoAP Server", "coap", {"version": "CoAP 1.0", "port": 5683}),
            ("AMQP Broker", "amqp", {"version": "AMQP 0-9-1", "port": 5672}),
            ("Bacnet Device", "bacnet", {"version": "BACnet/IP", "port": 47808}),
            ("EtherNet/IP Device", "ethernetip", {"version": "EtherNet/IP 1.0", "port": 2222}),
            # Web Application Honeypots
            ("GraphQL API", "graphql", {"server": "nginx/1.18.0", "paths": ["/graphql", "/api/graphql"]}),
            ("OAuth2 Server", "oauth2", {"server": "nginx/1.18.0", "paths": ["/oauth2/authorize", "/oauth2/token"]}),
            ("JWT Token Endpoint", "jwt", {"server": "nginx/1.18.0", "paths": ["/api/token", "/auth/jwt"]}),
            ("API Gateway", "apigateway", {"server": "nginx/1.18.0", "paths": ["/api/v1", "/api/v2"]}),
            ("WebSocket Server", "websocket", {"server": "nginx/1.18.0", "paths": ["/ws", "/websocket"]}),
            # Enterprise & Business Templates
            ("SAP Login Portal", "web", {"server": "nginx/1.18.0", "paths": ["/sap", "/sap/bc/gui/sap", "/sap/public/bc"], "app": "SAP"}),
            ("Oracle EBS", "web", {"server": "nginx/1.18.0", "paths": ["/OA_HTML", "/oracle", "/ebs"], "app": "Oracle EBS"}),
            ("SharePoint Server", "web", {"server": "Microsoft-IIS/10.0", "paths": ["/sharepoint", "/_layouts", "/_vti_bin"], "app": "SharePoint"}),
            ("Exchange OWA", "web", {"server": "Microsoft-IIS/10.0", "paths": ["/owa", "/ecp", "/ews"], "app": "Exchange"}),
            ("Citrix Gateway", "web", {"server": "Citrix-Gateway", "paths": ["/Citrix/Authentication", "/vpn/index.html"], "app": "Citrix"}),
            ("VPN Gateway (OpenVPN)", "vpn", {"type": "OpenVPN", "port": 1194, "protocol": "UDP"}),
            ("VPN Gateway (IPSec)", "vpn", {"type": "IPSec", "port": 500, "protocol": "UDP"}),
            ("Remote Desktop Gateway", "rdp", {"version": "RDP Gateway", "port": 3389, "gateway": True}),
            ("FileZilla FTP Server", "ftp", {"banner": "220 FileZilla Server", "port": 21, "version": "FileZilla 1.0"}),
            ("Atlassian Confluence", "web", {"server": "nginx/1.18.0", "paths": ["/confluence", "/wiki", "/rest"], "app": "Confluence"}),
            ("Jira Server", "web", {"server": "nginx/1.18.0", "paths": ["/jira", "/rest/api", "/secure"], "app": "Jira"}),
            # Security & Authentication Templates
            ("Active Directory LDAP", "ldap", {"version": "LDAPv3", "port": 389, "type": "ActiveDirectory"}),
            ("RADIUS Server", "radius", {"version": "RADIUS", "port": 1812, "protocol": "UDP"}),
            ("TACACS+ Server", "tacacs", {"version": "TACACS+", "port": 49, "protocol": "TCP"}),
            ("Kerberos KDC", "kerberos", {"version": "Kerberos 5", "port": 88, "protocol": "UDP"}),
            ("SAML IdP", "web", {"server": "nginx/1.18.0", "paths": ["/saml", "/idp", "/sso/saml"], "app": "SAML"}),
            ("OAuth2 Authorization Server", "oauth2", {"server": "nginx/1.18.0", "paths": ["/oauth2/authorize", "/oauth2/token"], "app": "OAuth2"}),
            ("2FA/MFA Server", "web", {"server": "nginx/1.18.0", "paths": ["/2fa", "/mfa", "/verify"], "app": "2FA"}),
            ("Certificate Authority (CA)", "ca", {"port": 443, "type": "PKI", "protocol": "HTTPS"}),
            # Development & DevOps Templates
            ("GitLab Server", "web", {"server": "nginx/1.18.0", "paths": ["/gitlab", "/api/v4", "/users/sign_in"], "app": "GitLab"}),
            ("Bitbucket Server", "web", {"server": "nginx/1.18.0", "paths": ["/bitbucket", "/rest/api", "/login"], "app": "Bitbucket"}),
            ("Nexus Repository", "web", {"server": "nginx/1.18.0", "paths": ["/nexus", "/service/rest", "/repository"], "app": "Nexus"}),
            ("Artifactory", "web", {"server": "nginx/1.18.0", "paths": ["/artifactory", "/api", "/ui"], "app": "Artifactory"}),
            ("SonarQube", "web", {"server": "nginx/1.18.0", "paths": ["/sonar", "/api", "/dashboard"], "app": "SonarQube"}),
            ("Harbor Registry", "web", {"server": "nginx/1.18.0", "paths": ["/harbor", "/api", "/v2"], "app": "Harbor"}),
            ("Prometheus", "web", {"server": "Prometheus", "paths": ["/metrics", "/api/v1", "/graph"], "app": "Prometheus"}),
            ("Grafana", "web", {"server": "nginx/1.18.0", "paths": ["/grafana", "/api", "/login"], "app": "Grafana"}),
            ("ELK Stack (Elasticsearch)", "elasticsearch", {"version": "Elasticsearch 7.15", "port": 9200, "app": "ELK"}),
            ("Splunk", "web", {"server": "nginx/1.18.0", "paths": ["/splunk", "/en-US", "/services"], "app": "Splunk"}),
            # Cloud Services Templates
            ("AWS EC2 Metadata", "aws", {"service": "EC2", "endpoint": "/latest/meta-data", "port": 80}),
            ("Azure Instance Metadata", "azure", {"service": "InstanceMetadata", "endpoint": "/metadata/instance", "port": 80}),
            ("GCP Metadata Server", "gcp", {"service": "Metadata", "endpoint": "/computeMetadata/v1", "port": 80}),
            ("DigitalOcean Metadata", "do", {"service": "Metadata", "endpoint": "/metadata/v1", "port": 80}),
            ("Cloudflare Tunnel", "cloudflare", {"service": "Tunnel", "endpoint": "/tunnel", "port": 80}),
            # Industrial & SCADA Templates
            ("Siemens S7 PLC", "s7", {"protocol": "S7", "port": 102, "vendor": "Siemens"}),
            ("Allen-Bradley PLC", "ab", {"protocol": "EtherNet/IP", "port": 2222, "vendor": "Rockwell"}),
            ("OPC-UA Server", "opcua", {"protocol": "OPC-UA", "port": 4840, "version": "1.04"}),
            ("DICOM Server", "dicom", {"protocol": "DICOM", "port": 104, "app": "Medical Imaging"}),
            ("BACnet/IP Device", "bacnet", {"version": "BACnet/IP", "port": 47808, "device": "Building Automation"}),
            ("LonWorks Device", "lonworks", {"protocol": "LonWorks", "port": 1628, "app": "Building Control"}),
            # Communication Templates
            ("IRC Server", "irc", {"version": "IRC", "port": 6667, "protocol": "TCP"}),
            ("XMPP Server", "xmpp", {"version": "XMPP", "port": 5222, "protocol": "TCP"}),
            ("Matrix Server", "matrix", {"version": "Matrix", "port": 8448, "protocol": "HTTPS"}),
            ("Rocket.Chat", "web", {"server": "nginx/1.18.0", "paths": ["/rocketchat", "/api", "/login"], "app": "Rocket.Chat"}),
            ("Mattermost", "web", {"server": "nginx/1.18.0", "paths": ["/mattermost", "/api/v4", "/login"], "app": "Mattermost"}),
        ]
        existing_templates = {t.name for t in db.query(models.HoneypotTemplate).all()}
        for name, t_type, cfg in default_templates:
            if name not in existing_templates:
                db.add(models.HoneypotTemplate(name=name, type=t_type, default_config=cfg))
        db.commit()
        
        # Seed MITRE mappings
        if db.query(models.MITREMapping).count() == 0:
            mappings = [
                models.MITREMapping(event_type="ssh_connection", technique_id="T1021", technique_name="Remote Services", tactic="Lateral Movement"),
                models.MITREMapping(event_type="ssh_command", technique_id="T1059", technique_name="Command and Scripting Interpreter", tactic="Execution"),
                models.MITREMapping(event_type="web_request", technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access"),
                models.MITREMapping(event_type="login_attempt", technique_id="T1110", technique_name="Brute Force", tactic="Credential Access"),
                models.MITREMapping(event_type="file_upload", technique_id="T1105", technique_name="Ingress Tool Transfer", tactic="Command and Control"),
                models.MITREMapping(event_type="sql_injection", technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access"),
            ]
            db.add_all(mappings)
            db.commit()
        
        # Create default organization if none exists
        if db.query(models.Organization).count() == 0:
            org = models.Organization(name="Default Organization")
            db.add(org)
            db.commit()
        
        # Seed detection lab scenarios
        from .detection_lab import seed_detection_lab_scenarios
        seed_detection_lab_scenarios(db)
    finally:
        db.close()
    
    # Start scheduler for scheduled reports
    from .scheduler import start_scheduler
    start_scheduler()
    
    yield
    
    # Shutdown: Stop scheduler
    from .scheduler import stop_scheduler
    stop_scheduler()


app = FastAPI(
    title="Honeypot Platform API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request timing and security headers middleware
from fastapi import Request
import time

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(round(process_time, 3))
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# Global exception handler
from fastapi.responses import JSONResponse

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    from .monitoring import log_event
    log_event("error", "Unhandled exception", 
              path=str(request.url.path), 
              method=request.method,
              error=str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error_id": id(exc)},
    )

app.include_router(setup_router, prefix="/api/v1", tags=["setup"])
app.include_router(auth_router)
app.include_router(core_router)
app.include_router(advanced_router)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for load balancers"""
    from .database import get_db
    from .monitoring import HealthChecker
    from fastapi.responses import JSONResponse
    
    db = next(get_db())
    try:
        health = HealthChecker.full_health_check(db)
        status_code = 200 if health["status"] == "healthy" else 503
        return JSONResponse(content=health, status_code=status_code)
    except Exception as e:
        from .monitoring import log_event
        log_event("error", "Health check failed", error=str(e))
        return JSONResponse(
            content={"status": "unhealthy", "error": str(e)},
            status_code=503,
        )

# Metrics endpoint
@app.get("/metrics")
async def metrics():
    """Prometheus-compatible metrics endpoint"""
    from .database import get_db
    from .performance import get_cached_metrics
    from fastapi.responses import Response
    
    db = next(get_db())
    try:
        metrics_data = get_cached_metrics(db)
        
        # Format as Prometheus metrics
        metrics_text = f"""# HELP honeypot_events_total Total number of events
# TYPE honeypot_events_total counter
honeypot_events_total {metrics_data['events']['total']}

# HELP honeypot_events_24h Events in last 24 hours
# TYPE honeypot_events_24h gauge
honeypot_events_24h {metrics_data['events']['last_24h']}

# HELP honeypot_iocs_total Total number of IOCs
# TYPE honeypot_iocs_total counter
honeypot_iocs_total {metrics_data['iocs']['total']}

# HELP honeypot_alerts_unread Unread alerts
# TYPE honeypot_alerts_unread gauge
honeypot_alerts_unread {metrics_data['alerts']['unread']}

# HELP honeypot_honeypots_active Active honeypots
# TYPE honeypot_honeypots_active gauge
honeypot_honeypots_active {metrics_data['honeypots']['active']}

# HELP honeypot_nodes_online Online nodes
# TYPE honeypot_nodes_online gauge
honeypot_nodes_online {metrics_data['nodes']['online']}
"""
        return Response(content=metrics_text, media_type="text/plain")
    except Exception as e:
        from .monitoring import log_event
        log_event("error", "Metrics collection failed", error=str(e))
        return JSONResponse(
            content={"error": str(e)},
            status_code=500,
        )




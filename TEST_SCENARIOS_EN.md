# 🧪 Honeypot Platform - Test Scenarios

This document contains comprehensive test scenarios for testing all features of the Honeypot Platform.

## 📋 Test Categories

1. [Installation and Setup](#1-installation-and-setup)
2. [Authentication](#2-authentication)
3. [Dashboard](#3-dashboard)
4. [Node Management](#4-node-management)
5. [Honeypot Management](#5-honeypot-management)
6. [Events and IOCs](#6-events-and-iocs)
7. [Alert System](#7-alert-system)
8. [Threat Intelligence](#8-threat-intelligence)
9. [Reports](#9-reports)
10. [Settings](#10-settings)
11. [Advanced Features](#11-advanced-features)
12. [API Tests](#12-api-tests)
13. [Security Tests](#13-security-tests)
14. [Performance Tests](#14-performance-tests)

---

## 1. Installation and Setup

### 1.1 Docker Compose Startup
- [ ] Run `docker-compose up -d` command
- [ ] All services start successfully (postgres, backend, frontend)
- [ ] Verify all containers are in "Up" state with `docker-compose ps`
- [ ] Backend health check: `curl http://localhost:8000/health` returns successful response

**Expected Result:** All services are running

### 1.2 Setup Wizard - Step 1: Database Configuration
- [ ] Navigate to `http://localhost:3000`
- [ ] Setup Wizard opens automatically
- [ ] Database connection status is checked
- [ ] "✓ Database Connected" message appears
- [ ] Database version and table count information is displayed
- [ ] Click "Next" button

**Expected Result:** Database connection successful, proceed to Step 2

### 1.3 Setup Wizard - Step 2: Admin Account
- [ ] Enter a valid email in the email field (e.g., admin@example.com)
- [ ] Enter a password with at least 8 characters
- [ ] Enter the same password in the confirm password field
- [ ] If passwords don't match, error message appears
- [ ] If password is less than 8 characters, error message appears
- [ ] When all fields are correctly filled, "Next" button becomes active
- [ ] Click "Next" button

**Expected Result:** Admin account information validated, proceed to Step 3

### 1.4 Setup Wizard - Step 3: Organization & SMTP
- [ ] Organization Name field appears (default: "Default Organization")
- [ ] Organization Name can be changed
- [ ] SMTP settings can be optionally entered
- [ ] SMTP fields can be left empty
- [ ] Click "Complete Setup" button
- [ ] "Setup Complete!" message appears
- [ ] Automatically redirected to login page after 2 seconds

**Expected Result:** Setup completed, redirected to login page

---

## 2. Authentication

### 2.1 Login
- [ ] Login page opens
- [ ] Login with email and password created during setup
- [ ] Attempt login with invalid email/password → Error message appears
- [ ] Attempt login with empty fields → Validation error appears
- [ ] After successful login, redirected to Dashboard

**Expected Result:** Login only possible with correct credentials

### 2.2 Logout
- [ ] Select "Logout" from user menu in top right
- [ ] Redirected to login page
- [ ] Token becomes invalid (requires re-login)

**Expected Result:** Successfully logged out

### 2.3 Token Expiry
- [ ] Login is performed
- [ ] Wait until token expires (24 hours)
- [ ] When token expires, API requests return 401
- [ ] Automatically redirected to login page

**Expected Result:** Re-login required when token expires

---

## 3. Dashboard

### 3.1 Dashboard Loading
- [ ] Dashboard opens after login
- [ ] All metrics are displayed:
  - [ ] Total Nodes
  - [ ] Total Honeypots
  - [ ] Active Sessions
  - [ ] Total IOCs
- [ ] Metrics show correct counts

**Expected Result:** Dashboard loads successfully, all metrics visible

### 3.2 Real-time Updates
- [ ] Create a new event while dashboard is open
- [ ] Real-time update arrives via WebSocket
- [ ] Metrics automatically update
- [ ] Recent Events list updates

**Expected Result:** Real-time updates work

### 3.3 Event Trends Chart
- [ ] "Event Trends (Last 24 Hours)" chart appears
- [ ] Chart displays correct data
- [ ] Chart is interactive (hover, zoom)

**Expected Result:** Chart renders successfully

### 3.4 Top Attackers Panel
- [ ] "Top Attackers" panel appears
- [ ] IPs with most attacks are listed
- [ ] Risk scores are displayed
- [ ] Click on IPs to navigate to detail page

**Expected Result:** Top attackers correctly listed

---

## 4. Node Management

### 4.1 Node List
- [ ] Navigate to Nodes page
- [ ] Existing nodes are listed (default: "Default Node")
- [ ] For each node, the following information is visible:
  - [ ] Node name
  - [ ] API Key (masked)
  - [ ] Status (online/offline)
  - [ ] Creation date

**Expected Result:** All nodes listed

### 4.2 Create New Node
- [ ] Click "Create Node" button
- [ ] Enter node name (e.g., "Production Node")
- [ ] Click "Create" button
- [ ] New node appears in list
- [ ] API Key is automatically generated

**Expected Result:** New node successfully created

### 4.3 Delete Node
- [ ] Select a node
- [ ] Click "Delete" button
- [ ] Confirmation message appears
- [ ] When confirmed, node is deleted
- [ ] If node has associated honeypots, warning is shown

**Expected Result:** Node successfully deleted (or warning shown)

### 4.4 View API Key
- [ ] Node's API Key is displayed
- [ ] Click "Show" button to view full key
- [ ] Copy key using "Copy" button

**Expected Result:** API Key correctly displayed and copied

---

## 5. Honeypot Management

### 5.1 Honeypot List
- [ ] Navigate to Honeypots page
- [ ] Existing honeypots are listed
- [ ] For each honeypot, the following information is visible:
  - [ ] Honeypot name
  - [ ] Template type
  - [ ] Port
  - [ ] Status (running/stopped)
  - [ ] Node

**Expected Result:** All honeypots listed

### 5.2 Create New Honeypot
- [ ] Click "Create Honeypot" button
- [ ] Form opens:
  - [ ] Name: Enter honeypot name
  - [ ] Template: Select template (SSH, Web, Database, etc.)
  - [ ] Node: Select node
  - [ ] Port: Enter port number (default port suggested based on template)
  - [ ] Listen IP: Enter IP address (default: 0.0.0.0)
- [ ] Click "Create" button
- [ ] New honeypot appears in list (status: stopped)

**Expected Result:** New honeypot successfully created

### 5.3 Start Honeypot
- [ ] Select a honeypot (status: stopped)
- [ ] Click "Start" button
- [ ] Honeypot is started
- [ ] Status updates to "running"
- [ ] Port starts listening

**Expected Result:** Honeypot successfully started

### 5.4 Stop Honeypot
- [ ] Select a running honeypot (status: running)
- [ ] Click "Stop" button
- [ ] Honeypot is stopped
- [ ] Status updates to "stopped"
- [ ] Port stops listening

**Expected Result:** Honeypot successfully stopped

### 5.5 Delete Honeypot
- [ ] Select a honeypot
- [ ] Click "Delete" button
- [ ] Confirmation message appears
- [ ] When confirmed, honeypot is deleted
- [ ] If honeypot is running, it is stopped first

**Expected Result:** Honeypot successfully deleted

### 5.6 Template Selection
- [ ] Select template when creating honeypot
- [ ] Default port is suggested based on template:
  - [ ] SSH → 2222
  - [ ] Web → 8080
  - [ ] Database → 3306
  - [ ] etc.
- [ ] When template changes, port suggestion updates

**Expected Result:** Template selection works correctly

---

## 6. Events and IOCs

### 6.1 SSH Honeypot Test
- [ ] Create and start SSH honeypot (port: 2222)
- [ ] Connect from terminal: `ssh -p 2222 test@localhost`
- [ ] Connection is successful
- [ ] Execute commands (e.g., `ls`, `pwd`, `whoami`)
- [ ] New events appear in Events page
- [ ] Event details are correctly recorded:
  - [ ] IP address
  - [ ] Event type (ssh_login, ssh_command, etc.)
  - [ ] Timestamp
  - [ ] Details

**Expected Result:** SSH honeypot works, events are recorded

### 6.2 Web Honeypot Test
- [ ] Create and start Web honeypot (port: 8080)
- [ ] Navigate to `http://localhost:8080` in browser
- [ ] Login page appears
- [ ] Test different paths:
  - [ ] `/login` → Login page
  - [ ] `/admin` → Admin panel
  - [ ] `/wp-admin` → WordPress admin
  - [ ] `/phpmyadmin` → phpMyAdmin
- [ ] New events appear in Events page
- [ ] Event details are correctly recorded

**Expected Result:** Web honeypot works, events are recorded

### 6.3 Database Honeypot Test
- [ ] Create and start Database honeypot (port: 3306)
- [ ] Connect with MySQL client: `mysql -h localhost -P 3306 -u root -p`
- [ ] Connection attempt is made
- [ ] New event appears in Events page
- [ ] Event details are correctly recorded

**Expected Result:** Database honeypot works, events are recorded

### 6.4 Events List
- [ ] Navigate to Events page
- [ ] All events are listed
- [ ] For each event, the following information is visible:
  - [ ] Timestamp
  - [ ] IP Address
  - [ ] Event Type
  - [ ] Honeypot
  - [ ] Details
- [ ] Pagination works
- [ ] Sorting works (timestamp, IP, type)

**Expected Result:** All events correctly listed

### 6.5 Events Filtering
- [ ] Filter events on Events page:
  - [ ] Filter by IP address
  - [ ] Filter by event type
  - [ ] Filter by date range
- [ ] Filter results are correctly displayed
- [ ] Filters can be cleared

**Expected Result:** Filtering works correctly

### 6.6 Events Export
- [ ] Click "Export CSV" button on Events page
- [ ] CSV file is downloaded
- [ ] CSV file is in correct format
- [ ] Click "Export JSON" button
- [ ] JSON file is downloaded
- [ ] JSON file is in correct format

**Expected Result:** Export operations successful

### 6.7 IOC Extraction
- [ ] Events are created
- [ ] IOC Extractor automatically runs
- [ ] Navigate to IOCs page
- [ ] Extracted IOCs are visible:
  - [ ] IP Addresses
  - [ ] URLs
  - [ ] Hashes
  - [ ] Credentials
- [ ] Risk score is shown for each IOC

**Expected Result:** IOCs automatically extracted

### 6.8 IOC List
- [ ] Navigate to IOCs page
- [ ] All IOCs are listed
- [ ] For each IOC, the following information is visible:
  - [ ] Value
  - [ ] Type
  - [ ] Risk Score
  - [ ] First Seen
  - [ ] Last Seen
- [ ] Sorting by risk score is possible

**Expected Result:** All IOCs correctly listed

### 6.9 IOC Filtering
- [ ] Filter IOCs on IOCs page:
  - [ ] Search by value
  - [ ] Filter by type
  - [ ] Filter by min risk score
- [ ] Filter results are correctly displayed

**Expected Result:** IOC filtering works correctly

### 6.10 IOC Enrichment
- [ ] Select an IOC
- [ ] Click "Enrich" button
- [ ] Threat intelligence information is loaded
- [ ] Enrichment results are displayed:
  - [ ] Reputation score
  - [ ] Threat intelligence data
  - [ ] Historical data

**Expected Result:** IOC enrichment successful

### 6.11 IOC Export
- [ ] Click "Export CSV" button on IOCs page
- [ ] CSV file is downloaded
- [ ] Click "Export JSON" button
- [ ] JSON file is downloaded

**Expected Result:** IOC export successful

---

## 7. Alert System

### 7.1 Alert Creation
- [ ] Create a high-risk event
- [ ] Alert is automatically created
- [ ] Navigate to Alerts page
- [ ] New alert appears
- [ ] Alert details are correct:
  - [ ] Severity (high/medium/low)
  - [ ] Message
  - [ ] Timestamp
  - [ ] Related Event

**Expected Result:** Alert automatically created

### 7.2 Alert List
- [ ] Navigate to Alerts page
- [ ] All alerts are listed
- [ ] Unread alerts are highlighted
- [ ] Alerts are color-coded by severity

**Expected Result:** Alerts correctly listed

### 7.3 Mark Alert as Read
- [ ] Select an alert
- [ ] Alert details are displayed
- [ ] Alert is automatically marked as "read"
- [ ] Unread count is updated

**Expected Result:** Alert marked as read

### 7.4 Alert Rules
- [ ] Navigate to Alert Rules page
- [ ] Existing alert rules are listed
- [ ] Create new alert rule:
  - [ ] Rule name
  - [ ] Condition (event type, IOC type, risk score, etc.)
  - [ ] Action (create alert, send email, block IP, etc.)
- [ ] Rule is saved
- [ ] Rule becomes active

**Expected Result:** Alert rule successfully created

---

## 8. Threat Intelligence

### 8.1 Threat Map
- [ ] Navigate to Threat Map page
- [ ] World map is displayed
- [ ] Attack sources are shown on map
- [ ] Hover over IPs to see details
- [ ] Attack counts by country are visible

**Expected Result:** Threat map works correctly

### 8.2 IOC Enrichment (Threat Intel)
- [ ] Select an IOC
- [ ] Click "Enrich" button
- [ ] Information is fetched from threat intelligence feeds:
  - [ ] AbuseIPDB
  - [ ] VirusTotal
  - [ ] OTX
  - [ ] MISP
- [ ] Enrichment results are displayed

**Expected Result:** Threat intelligence enrichment successful

### 8.3 Threat Intel Feeds
- [ ] Navigate to Threat Intel page
- [ ] Existing feeds are listed
- [ ] Add new feed:
  - [ ] Feed name
  - [ ] Feed type
  - [ ] API key
- [ ] Feed is tested
- [ ] Feed becomes active

**Expected Result:** Threat intel feed successfully added

---

## 9. Reports

### 9.1 HTML Report
- [ ] Navigate to Reports page
- [ ] Select date range
- [ ] Click "Generate HTML Report" button
- [ ] HTML report is created
- [ ] Report content is correct:
  - [ ] Summary statistics
  - [ ] Event list
  - [ ] IOC list
  - [ ] Charts

**Expected Result:** HTML report successfully created

### 9.2 JSON Report
- [ ] Click "Generate JSON Report" button on Reports page
- [ ] JSON report is created
- [ ] JSON file is downloaded
- [ ] JSON format is correct

**Expected Result:** JSON report successfully created

### 9.3 PDF Report
- [ ] Click "Generate PDF Report" button on Reports page
- [ ] PDF report is created
- [ ] PDF file is downloaded
- [ ] PDF content is correct:
  - [ ] Cover page
  - [ ] Executive summary
  - [ ] Detailed analysis
  - [ ] Charts and graphs
  - [ ] Recommendations

**Expected Result:** PDF report successfully created

### 9.4 Scheduled Reports
- [ ] Navigate to "Scheduled Reports" section on Reports page
- [ ] Create new scheduled report:
  - [ ] Report name
  - [ ] Report type (HTML/JSON/PDF)
  - [ ] Schedule (daily/weekly/monthly)
  - [ ] Email recipients
- [ ] Scheduled report is saved
- [ ] Report is automatically created and sent at scheduled time

**Expected Result:** Scheduled report successfully created

---

## 10. Settings

### 10.1 SMTP Settings
- [ ] Navigate to Settings page
- [ ] Configure SMTP settings:
  - [ ] SMTP Host
  - [ ] SMTP Port
  - [ ] SMTP Username
  - [ ] SMTP Password
- [ ] Click "Test Connection" button
- [ ] Connection is tested
- [ ] Settings are saved

**Expected Result:** SMTP settings successfully configured

### 10.2 Email Notifications
- [ ] SMTP settings are configured
- [ ] Create a high-risk alert
- [ ] Email is sent
- [ ] Email content is correct:
  - [ ] Alert details
  - [ ] Event information
  - [ ] IOC information

**Expected Result:** Email notifications work

---

## 11. Advanced Features

### 11.1 MITRE ATT&CK Mapping
- [ ] Navigate to MITRE ATT&CK page
- [ ] Events are mapped to MITRE techniques
- [ ] MITRE matrix is displayed
- [ ] Event counts for each technique are visible

**Expected Result:** MITRE mapping works correctly

### 11.2 Playbooks
- [ ] Navigate to Playbooks page
- [ ] Create new playbook:
  - [ ] Playbook name
  - [ ] Trigger condition
  - [ ] Actions (block IP, send email, create incident, etc.)
- [ ] Playbook is saved
- [ ] Playbook is tested

**Expected Result:** Playbook successfully created and works

### 11.3 Campaigns
- [ ] Navigate to Campaigns page
- [ ] Create new campaign:
  - [ ] Campaign name
  - [ ] Description
  - [ ] Honeypots (honeypots to include in campaign)
- [ ] Campaign is saved
- [ ] Campaign statistics are displayed

**Expected Result:** Campaign successfully created

### 11.4 Attack Replay
- [ ] Navigate to Attack Replay page
- [ ] Select a session
- [ ] Click "Replay" button
- [ ] Session replay is displayed
- [ ] Timeline is displayed
- [ ] Events are shown in sequence

**Expected Result:** Attack replay works correctly

### 11.5 Behavioral Analysis
- [ ] Navigate to Behavioral Analysis page
- [ ] Anomaly detection is performed:
  - [ ] Brute force attacks
  - [ ] Port scanning
  - [ ] Credential stuffing
- [ ] Anomalies are listed
- [ ] Anomaly details are displayed

**Expected Result:** Behavioral analysis works correctly

### 11.6 ML Anomaly Detection
- [ ] Navigate to ML Anomaly page
- [ ] ML model is run
- [ ] Anomalies are detected
- [ ] Anomaly scores are displayed
- [ ] Anomaly details are displayed

**Expected Result:** ML anomaly detection works

### 11.7 SIEM Integration
- [ ] Navigate to SIEM Integration page
- [ ] Add new SIEM integration:
  - [ ] SIEM type (Splunk, QRadar, Elasticsearch, etc.)
  - [ ] Connection details
  - [ ] Authentication
- [ ] Integration is tested
- [ ] Events are sent to SIEM

**Expected Result:** SIEM integration successful

### 11.8 Geo-Blocking
- [ ] Navigate to Geo-Blocking page
- [ ] Create new geo-block rule:
  - [ ] Rule name
  - [ ] Countries (countries to block)
  - [ ] Action (block/allow/alert)
- [ ] Rule is saved
- [ ] Rule becomes active

**Expected Result:** Geo-blocking works correctly

### 11.9 Rate Limiting
- [ ] Navigate to Rate Limiting page
- [ ] Create new rate limit rule:
  - [ ] Rule name
  - [ ] Limit type (IP, event type, honeypot)
  - [ ] Rate limit (e.g., 10 requests/minute)
- [ ] Rule is saved
- [ ] Rate limit is tested

**Expected Result:** Rate limiting works correctly

### 11.10 Honeytokens
- [ ] Navigate to Honeytokens page
- [ ] Create new honeytoken:
  - [ ] Token name
  - [ ] Token type (credential, API key, file, URL)
  - [ ] Token value
- [ ] Token is saved
- [ ] Alert is created when token is used

**Expected Result:** Honeytoken successfully created

### 11.11 YARA Rules
- [ ] Navigate to YARA Rules page
- [ ] Create new YARA rule:
  - [ ] Rule name
  - [ ] Rule content
- [ ] Rule is saved
- [ ] Rule matches in events

**Expected Result:** YARA rules work correctly

### 11.12 Compliance
- [ ] Navigate to Compliance page
- [ ] Compliance reports are displayed:
  - [ ] GDPR
  - [ ] HIPAA
  - [ ] PCI-DSS
  - [ ] ISO 27001
- [ ] Reports are generated

**Expected Result:** Compliance reports are created

---

## 12. API Tests

### 12.1 Authentication API
- [ ] Test `POST /api/v1/auth/login` endpoint
- [ ] Get token with valid credentials
- [ ] Invalid credentials return 401
- [ ] Make authenticated request with token

**Expected Result:** Authentication API works correctly

### 12.2 Nodes API
- [ ] `GET /api/v1/nodes` - Get node list
- [ ] `POST /api/v1/nodes` - Create new node
- [ ] `GET /api/v1/nodes/{id}` - Get node details
- [ ] `DELETE /api/v1/nodes/{id}` - Delete node

**Expected Result:** Nodes API works correctly

### 12.3 Honeypots API
- [ ] `GET /api/v1/honeypots` - Get honeypot list
- [ ] `POST /api/v1/honeypots` - Create new honeypot
- [ ] `POST /api/v1/honeypots/{id}/start` - Start honeypot
- [ ] `POST /api/v1/honeypots/{id}/stop` - Stop honeypot
- [ ] `DELETE /api/v1/honeypots/{id}` - Delete honeypot

**Expected Result:** Honeypots API works correctly

### 12.4 Events API
- [ ] `GET /api/v1/events` - Get event list
- [ ] `GET /api/v1/events?ip=1.2.3.4` - Filter by IP
- [ ] `GET /api/v1/events?type=ssh_login` - Filter by type
- [ ] Test export endpoints

**Expected Result:** Events API works correctly

### 12.5 IOCs API
- [ ] `GET /api/v1/iocs` - Get IOC list
- [ ] `GET /api/v1/iocs/{id}/enrich` - IOC enrichment
- [ ] Test export endpoints

**Expected Result:** IOCs API works correctly

### 12.6 Health Check API
- [ ] `GET /health` - Perform health check
- [ ] Response is in correct format:
  - [ ] Status (healthy/unhealthy)
  - [ ] Database status
  - [ ] System resources
  - [ ] Honeypot services

**Expected Result:** Health check works correctly

### 12.7 WebSocket API
- [ ] Establish WebSocket connection: `ws://localhost:8000/api/v1/ws`
- [ ] Receive real-time events
- [ ] Alerts arrive in real-time
- [ ] Close connection

**Expected Result:** WebSocket works correctly

---

## 13. Security Tests

### 13.1 Authentication Security
- [ ] Make request with invalid token → Returns 401
- [ ] Make request with expired token → Returns 401
- [ ] Make request without token → Returns 401
- [ ] Attempt SQL injection → Secure

**Expected Result:** Authentication is secure

### 13.2 Input Validation
- [ ] Attempt XSS → Secure
- [ ] Attempt SQL injection → Secure
- [ ] Attempt command injection → Secure
- [ ] Attempt path traversal → Secure

**Expected Result:** Input validation is secure

### 13.3 Rate Limiting
- [ ] Exceed rate limit → Returns 429
- [ ] After rate limit period expires, retry → Successful

**Expected Result:** Rate limiting works

### 13.4 IP Blocking
- [ ] Block an IP
- [ ] Make request from blocked IP → Blocked
- [ ] Unblock IP → Accessible again

**Expected Result:** IP blocking works

### 13.5 CORS
- [ ] Make request from different origin
- [ ] CORS headers are correctly set
- [ ] Only allowed origins can access

**Expected Result:** CORS correctly configured

---

## 14. Performance Tests

### 14.1 Load Test
- [ ] Test with 100 concurrent users
- [ ] Measure response times
- [ ] Check error rate
- [ ] Check memory usage

**Expected Result:** System works stably under load

### 14.2 Database Performance
- [ ] Create large number of events (10,000+)
- [ ] Measure query performance
- [ ] Verify indexes are working
- [ ] Check pagination performance

**Expected Result:** Database performance is adequate

### 14.3 Real-time Performance
- [ ] 1000+ concurrent WebSocket connections
- [ ] Measure real-time update performance
- [ ] Check for memory leaks

**Expected Result:** Real-time performance is adequate

---

## 📊 Test Results

Record test results here:

### Test Date: _______________
### Tested Version: _______________
### Tested By: _______________

### Overall Result:
- [ ] ✅ All tests passed
- [ ] ⚠️ Some tests failed (details below)
- [ ] ❌ Many tests failed

### Failed Tests:
1. _________________________
2. _________________________
3. _________________________

### Notes:
_________________________________________________
_________________________________________________
_________________________________________________

---

## 🔄 Test Checklist

Check off each test category after completion:

- [ ] 1. Installation and Setup
- [ ] 2. Authentication
- [ ] 3. Dashboard
- [ ] 4. Node Management
- [ ] 5. Honeypot Management
- [ ] 6. Events and IOCs
- [ ] 7. Alert System
- [ ] 8. Threat Intelligence
- [ ] 9. Reports
- [ ] 10. Settings
- [ ] 11. Advanced Features
- [ ] 12. API Tests
- [ ] 13. Security Tests
- [ ] 14. Performance Tests

---

**Test Scenarios v1.0**  
*Last Updated: 2024*


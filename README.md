# 🍯 Honeypot Platform - Enterprise-Grade Threat Detection

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-blue.svg)](https://reactjs.org/)

Enterprise-grade honeypot management platform with advanced threat detection, analytics, and automation capabilities. Deploy, monitor, and analyze cyber threats in real-time.

## ✨ Features

### 🎯 Core Capabilities
- **100+ Honeypot Templates**: SSH, Web, Database, ICS, SMTP, FTP, Telnet, RDP, VNC, SMB, SNMP, LDAP, and more
- **Multi-Node Support**: Deploy honeypots across multiple nodes and locations
- **Real-time Monitoring**: WebSocket-based real-time notifications and updates
- **Threat Intelligence**: IOC enrichment, threat actor attribution, and reputation scoring
- **Advanced Analytics**: Attack correlation, heatmaps, trend analysis, and behavioral detection
- **Automation**: Playbooks, auto-response, alert rules, and scheduled reports
- **SIEM Integration**: Splunk, QRadar, ArcSight, LogRhythm, Zabbix, Logsign, Elasticsearch, Graylog, Wazuh, OSSIM, Security Onion

### 🔒 Security Features
- **Rate Limiting**: IP, event type, and honeypot-based rate limiting
- **IP Blocking**: Automatic and manual IP blocking with geo-blocking support
- **Honeytokens**: Credential, API key, file, and URL honeytokens
- **YARA Rules**: Pattern matching engine for threat detection
- **Geo-Blocking**: Country-based access control
- **Time-Based Rules**: Time window-based access control

### 📊 Production Features
- **Health Checks**: `/health` endpoint for load balancers
- **Metrics**: Prometheus-compatible `/metrics` endpoint
- **Structured Logging**: JSON-formatted logs for easy parsing
- **Performance Optimization**: Caching, database indexing, async processing
- **Automated Backups**: Database backup and restore functionality
- **Error Handling**: Global exception handling with detailed error messages
- **Security Headers**: XSS protection, frame options, HSTS

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- 2GB+ RAM
- 10GB+ disk space

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/muhammetoztrk/honeypot-platform.git
cd honeypot-platform
```

2. **Configure environment variables (optional for development):**
```bash
# Create .env file (optional - defaults are provided for development)
cat > .env << EOF
POSTGRES_PASSWORD=your-secure-password
JWT_SECRET=your-jwt-secret-key
EOF
```

⚠️ **Important**: For production, always set `POSTGRES_PASSWORD` and `JWT_SECRET` via environment variables or `.env` file.

3. **Start the platform:**
```bash
docker-compose up -d
```

4. **Access Setup Wizard:**
   - Open `http://localhost:3000` in your browser
   - Complete the 3-step setup wizard:
     - Database Configuration (automatic)
     - Admin Account Creation
     - Organization & SMTP Settings (optional)

5. **Login and start using:**
   - Use the admin credentials you created during setup
   - Create your first node and honeypot
   - Start monitoring threats!

## 📖 Documentation

- **[GitHub Setup Guide](GITHUB_SETUP.md)** - How to set up and deploy on GitHub
- **[LinkedIn Promotion Guide](LINKEDIN_PROMOTION.md)** - Marketing and promotion tips

## 🏗️ Architecture

### Backend
- **Framework**: FastAPI (Python 3.12)
- **Database**: PostgreSQL 15
- **Authentication**: JWT tokens
- **API**: RESTful API with OpenAPI documentation

### Frontend
- **Framework**: React 18 with TypeScript
- **UI**: Dark/Light theme support
- **Real-time**: WebSocket connections
- **Charts**: Recharts for visualization

### Infrastructure
- **Containerization**: Docker Compose
- **Web Server**: Nginx (frontend)
- **Process Manager**: Uvicorn (backend)

## 🔌 API Documentation

Interactive API documentation is available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### Key Endpoints

#### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login and get token

#### Core
- `GET /api/v1/nodes` - List nodes
- `GET /api/v1/honeypots` - List honeypots
- `GET /api/v1/events` - List events
- `GET /api/v1/iocs` - List IOCs
- `GET /api/v1/alerts` - List alerts

#### Monitoring
- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics

## 🔐 Security

### Production Checklist
- [ ] Set `POSTGRES_PASSWORD` via `.env` file or environment variable
- [ ] Set `JWT_SECRET` via `.env` file or environment variable
- [ ] Configure SMTP settings for email notifications
- [ ] Enable HTTPS (use reverse proxy like Nginx)
- [ ] Set up firewall rules
- [ ] Configure rate limiting
- [ ] Enable audit logging
- [ ] Set up automated backups
- [ ] Review and update security headers

### Environment Variables

Create a `.env` file in the project root:

```env
# Database
POSTGRES_PASSWORD=your-secure-password-here

# JWT Secret (use a strong random string)
JWT_SECRET=your-jwt-secret-key-here

# Optional: SMTP Configuration
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-email@example.com
SMTP_PASSWORD=your-smtp-password
ALERT_EMAIL=alerts@example.com
```

## 📈 Roadmap

- [ ] Kubernetes deployment support
- [ ] Mobile app (React Native)
- [ ] CLI tool
- [ ] Browser extension
- [ ] Multi-language support
- [ ] High-interaction honeypots
- [ ] Machine learning enhancements

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Muhammet Ali Öztürk**
- GitHub: [@muhammetoztrk](https://github.com/muhammetoztrk)
- LinkedIn: [Muhammet Ali Öztürk](https://www.linkedin.com/in/muhammetoztrk/)

## 🙏 Acknowledgments

- FastAPI for the amazing web framework
- React for the frontend framework
- PostgreSQL for the database
- All the open-source contributors

## ⭐ Show Your Support

Give a ⭐️ if this project helped you!

---

**Made with ❤️ for the cybersecurity community**


# 🛡️ VigilEdge WAF - Advanced Web Application Firewall

[![Python Version](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-009688.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-WAF-red.svg)](https://github.com)
[![Status](https://img.shields.io/badge/status-active-success.svg)](https://github.com)

> **A professional-grade Web Application Firewall (WAF) with built-in threat detection, real-time alerting, and comprehensive security monitoring capabilities.**

<div align="center">
  
  **[Features](#️-features)** • **[Quick Start](#-quick-start)** • **[Documentation](#-api-endpoints)** • **[Demo](#-demo)** • **[Contributing](#-contributing)**
  
</div>

---

> Launcher names changed in the workspace root: use `start_demo.bat` for the original demo flow and `start_custom_website.bat` for a custom site behind the WAF. Mentions of `start_both.bat` below are legacy documentation.

## 🌟 Overview

VigilEdge WAF is an enterprise-grade web application firewall designed to protect web applications from common security threats including **SQL injection**, **XSS attacks**, **DDoS attempts**, and more. Built with **FastAPI** and **Python 3.13+**, it provides:

- ⚡ **Real-time threat detection** with instant blocking
- 📊 **Live monitoring dashboard** with WebSocket updates
- 🔒 **Session-based authentication** preventing URL bypass
- 🌐 **Mobile-responsive UI** optimized for all devices
- 📡 **RESTful API** for IP management and event logs
- 🎯 **Zero-config startup** with automated setup scripts

## 🛡️ Features

### Core Security Features
- **SQL Injection Protection**: Enterprise-grade detection with 100+ advanced patterns including WAF bypass, error-based, polyglot, and database-specific attacks
- **XSS Prevention**: Cross-site scripting attack mitigation  
- **Rate Limiting**: Configurable request rate limiting per IP/endpoint
- **IP Blocking**: Dynamic IP blacklisting with CRUD operations
- **DDoS Protection**: Traffic analysis and automatic mitigation
- **Bot Detection**: Advanced bot and crawler identification
- **Path Traversal Protection**: Directory traversal attack prevention

### Monitoring & Alerting
- **Real-time Dashboard**: Live security monitoring with responsive design
- **Mobile Optimized**: Full responsive layout for tablets and smartphones
- **Dynamic Event Logs**: Real-time security event tracking with filtering
- **Blocked IPs Management**: Full CRUD API for IP blacklist management
- **WebSocket Alerts**: Instant threat notifications
- **Traffic Analysis**: Comprehensive request/response logging

### Administration
- **Session-Based Authentication**: Secure admin access with session cookies
- **Protected Admin Panel**: Session validation prevents URL-based bypass
- **Professional Login UI**: Glassmorphism design with security badges
- **Configuration Management**: Dynamic rule updates via YAML
- **API Integration**: RESTful API for blocked IPs and event logs

## 🚀 Quick Start

### 📦 Prerequisites

| Requirement | Version | Purpose |
|------------|---------|---------|
| Python | 3.13+ | Core runtime |
| FastAPI | 0.104.1+ | Web framework |
| SQLite | Built-in | Database |
| Uvicorn | Latest | ASGI server |

### ⚡ One-Click Startup (Windows)

```bash
# Navigate to project root
cd "vigiledge part 3"

# Double-click or run:
start_demo.bat
```

**That's it!** The demo launcher starts the WAF, ThreatLoom, chatbot bridge, and vulnerable test app automatically.

### 🔧 Manual Installation

#### 1️⃣ Clone the Repository
```bash
git clone https://github.com/yourusername/vigiledge-waf.git
cd vigiledge-waf
```

#### 2️⃣ Install Dependencies
```bash
cd VigilEdge
pip install -r waf/requirements.txt
```

#### 3️⃣ Start Applications

**Option A: Automated Start (Recommended)**
```bash
# Windows - From project root
cd ..
start_demo.bat

# Or use the custom upstream launcher from the workspace root
start_custom_website.bat
```

**Option B: Manual Start**
```bash
# Terminal 1 - Start Vulnerable App
cd vulnerable-app
python app.py

# Terminal 2 - Start WAF (in new terminal)
cd waf
python main.py
```

### 🌐 Access Points

| Service | URL | Description |
|---------|-----|-------------|
| **WAF Login** | http://localhost:5000/login | Operator login or first-run bootstrap |
| **WAF Dashboard** | http://localhost:5000/admin/dashboard | Main monitoring interface |
| **Protected App** | http://localhost:5000/protected/ | Proxied vulnerable app |
| **Admin Panel** | http://localhost:5000/protected/admin | Admin interface (password: `admin123`) |
| **API Docs** | http://localhost:5000/docs | Interactive API documentation when debug is enabled |
| **Direct App** | http://localhost:8080/ | Unprotected app (bypasses WAF) |

> **💡 Tip**: The browser will automatically open to `http://localhost:5000/protected` after startup!

## 📊 Dashboard Access

- **WAF Login**: http://localhost:5000/login
- **WAF Dashboard**: http://localhost:5000/admin/dashboard (authentication required)
- **Vulnerable App (Protected)**: http://localhost:5000/protected/
- **Vulnerable App Admin**: http://localhost:5000/protected/admin
- **Direct Vulnerable App**: http://localhost:8080/ (Bypasses WAF)
- **API Documentation**: http://localhost:5000/docs when debug is enabled

### Authentication
- **WAF Dashboard**: Signed session-based admin authentication with first-run bootstrap
- **WAF 2FA**: Google Authenticator compatible TOTP enrollment and password recovery
- **Vulnerable App Admin Panel**: Session-based authentication
  - Password: `admin123`
  - Session cookies prevent URL-based bypass attacks

## 🔧 Configuration

### WAF Rules Configuration
Edit `config/waf_rules.yaml` to customize security rules:

```yaml
sql_injection:
  enabled: true
  patterns:
    - "union.*select"
    - "drop.*table"
    - "' or '1'='1"
  
xss:
  enabled: true
  patterns:
    - "<script"
    - "javascript:"
    - "onerror="

rate_limiting:
  enabled: true
  requests_per_minute: 100
```

### Session Configuration
- WAF admin session: signed JWT-backed cookie
- Session cookies: HTTP-only with environment-aware secure flag
- Session invalidation: existing WAF sessions are invalidated on admin password change
- Vulnerable app admin password: `admin123` inside the demo app only

### Environment Variables
Create a `.env` file in the `waf/` directory:

```env
# Server Configuration
HOST=127.0.0.1
PORT=5000
DEBUG=False
ENVIRONMENT=production

# Security Settings
SECRET_KEY=replace-with-a-random-secret
CONTROL_PLANE_API_TOKENS=replace-with-service-token
BOOTSTRAP_ADMIN_TOKEN=replace-with-bootstrap-token
SQL_INJECTION_PROTECTION=True
XSS_PROTECTION=True
DDOS_PROTECTION=True
RATE_LIMIT_ENABLED=True
RATE_LIMIT_REQUESTS=100
TRUSTED_REVERSE_PROXIES=127.0.0.1,::1

# Logging
LOG_LEVEL=INFO
LOG_FILE=./logs/vigiledge.log

# Vulnerable App
VULNERABLE_APP_URL=http://localhost:8080
VULNERABLE_APP_ENABLED=True
```

## HTTPS and Reverse Proxy Deployment

For real deployments, do not expose the WAF directly on plain HTTP. The intended deployment pattern is:

1. Run VigilEdge WAF on `127.0.0.1:5000` or another private interface.
2. Put a TLS terminator or reverse proxy in front of it.
3. Set `TRUSTED_REVERSE_PROXIES` so forwarded client IP headers are only trusted from that proxy.

### Recommended Default: Caddy

For non-expert users, Caddy is the easiest option because it can handle certificates automatically.

```caddy
example.com {
  reverse_proxy 127.0.0.1:5000
}
```

WAF `.env`:

```env
TRUSTED_REVERSE_PROXIES=127.0.0.1,::1
```

### Nginx Example

```nginx
server {
  listen 80;
  server_name example.com;
  return 301 https://$host$request_uri;
}

server {
  listen 443 ssl http2;
  server_name example.com;

  ssl_certificate /path/to/fullchain.pem;
  ssl_certificate_key /path/to/privkey.pem;

  location / {
    proxy_pass http://127.0.0.1:5000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

### Traefik or Another Local TLS Terminator

The same model applies:

- terminate HTTPS in the proxy
- forward to the WAF over localhost or a private subnet
- set `TRUSTED_REVERSE_PROXIES` to the proxy host IP or Docker/network CIDR

Example:

```env
TRUSTED_REVERSE_PROXIES=127.0.0.1,::1,172.18.0.0/16
```

### Important Notes

- Leave `TRUSTED_REVERSE_PROXIES` empty if the WAF is not behind a proxy.
- Do not trust broad ranges like `0.0.0.0/0`.
- If this setting is too broad, attackers can spoof `X-Forwarded-For`.
- If this setting is missing behind a proxy, logs and rate limits will show the proxy IP instead of the real client IP.

## ⚡ Performance & Specifications

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 2 GB | 4+ GB |
| **Storage** | 100 MB | 500 MB |
| **OS** | Windows 10+ | Windows 11 |
| **Python** | 3.13+ | 3.13+ |

### Performance Metrics

- **Request Processing**: < 10ms average latency
- **Threat Detection**: Real-time (< 5ms)
- **Dashboard Updates**: WebSocket live streaming
- **Concurrent Connections**: 1000+ supported
- **Database**: SQLite with auto-optimization
- **Memory Usage**: ~100-150 MB (idle)

### Technology Stack

```
Backend:
├── FastAPI 0.104.1         # Async web framework
├── Uvicorn                 # ASGI server
├── Python 3.13+            # Core language
└── SQLite3                 # Database

Frontend:
├── HTML5/CSS3              # Structure & styling
├── JavaScript (ES6+)       # Interactivity
├── WebSockets              # Real-time updates
└── Responsive Design       # Mobile optimization

Security:
├── Custom WAF Engine       # Threat detection
├── Pattern Matching        # SQL/XSS detection
├── Rate Limiting           # DDoS protection
└── IP Blacklisting         # Access control
```

## 🏗️ Project Structure

```
VigilEdge/
├── waf/                           # WAF Application (Port 5000)
│   ├── main.py                   # WAF Dashboard & Proxy
│   ├── vigiledge/                # Core WAF Package
│   │   ├── core/                 # Security engines
│   │   │   ├── waf_engine.py    # Threat detection engine
│   │   │   └── security_manager.py
│   │   ├── middleware/           # Request filtering
│   │   │   └── security_middleware.py
│   │   ├── api/                  # REST APIs
│   │   │   └── routes.py
│   │   └── utils/                # Utilities
│   │       └── logger.py
│   ├── config/                   # Configuration
│   │   └── waf_rules.yaml       # Security rules
│   ├── templates/                # Dashboard HTML
│   └── static/                   # CSS/JS assets
├── vulnerable-app/               # Vulnerable App (Port 8080)
│   ├── app.py                   # E-commerce demo app
│   └── vulnerable.db            # SQLite database
├── scripts/                      # Automation scripts
│   ├── start_both.bat           # Start WAF + Vulnerable App
│   └── setup.bat                # Environment setup
├── docs/                         # Documentation
│   ├── PROJECT_REPORT_CHAPTERS.md
│   └── TESTING_README.md
└── tests/                        # Test suites

Flow: Browser → WAF (5000) → /protected/ → Vulnerable App (8080)
```

## 📝 API Endpoints

### Blocked IPs Management
```bash
# Get all blocked IPs
GET http://localhost:5000/api/v1/blocked-ips

# Block an IP
POST http://localhost:5000/api/v1/blocked-ips
{"ip": "192.168.1.100", "reason": "Suspicious activity"}

# Unblock an IP
DELETE http://localhost:5000/api/v1/blocked-ips/192.168.1.100

# Clear all blocked IPs
DELETE http://localhost:5000/api/v1/blocked-ips
```

### Event Logs
```bash
# Get security event logs
GET http://localhost:5000/api/v1/event-logs
```

### WAF Proxy
```bash
# Access vulnerable app through WAF protection
GET http://localhost:5000/protected/
POST http://localhost:5000/protected/admin/login
```

## 🔍 Testing WAF Protection

### XSS Attack Test
1. Navigate to: http://localhost:5000/protected/admin
2. Enter payload: `<script>alert('XSS')</script>`
3. **Expected**: WAF blocks with "🛡️ BLOCKED BY WAF - Threat Type: XSS"

### SQL Injection Test
1. Navigate to vulnerable app search or login
2. Enter payload: `' OR '1'='1`
3. **Expected**: Request blocked by WAF with threat details

### URL Bypass Test (Authentication)
1. Login at: http://localhost:5000/login with your WAF admin account
2. Copy URL to new browser/incognito window
3. **Expected**: Redirects to login (session-based auth prevents bypass)

### Monitoring Features
- **Real-time Dashboard**: Live threat detection statistics
- **Event Logs**: Detailed security event tracking with timestamps
- **Blocked IPs**: Dynamic IP management with add/remove functionality
- **Mobile Responsive**: Optimized for desktop, tablet, and smartphone

## 🎯 Key Features Implemented

### Security Enhancements
- ✅ Session-based authentication (prevents URL-based bypass)
- ✅ XSS and SQL injection detection and blocking
- ✅ Real-time threat detection with event logging
- ✅ Dynamic IP blocking with CRUD API
- ✅ Path traversal protection
- ✅ Content-type based response handling (JSON/HTML)

### UI/UX Improvements
- ✅ Mobile responsive design (80px hero on mobile, flexbox layout)
- ✅ Professional glassmorphism login page
- ✅ Dynamic event logs with real WAF data
- ✅ Live blocked IPs management interface
- ✅ Security badges and SSL indicators
- ✅ Desktop/mobile sidebar optimization

### API Features
- ✅ RESTful blocked IPs endpoints (GET, POST, DELETE, clear all)
- ✅ Event logs API with security event details
- ✅ Session cookie management
- ✅ Proper error handling and JSON responses

## 🎬 Demo

### Live Testing Walkthrough

1. **Start the System**
   ```bash
   start_both.bat
   ```

2. **Open Dashboard**
   - Navigate to http://localhost:5000/dashboard
   - View real-time security metrics
   - Monitor active threats and blocked IPs

3. **Test SQL Injection Protection**
   ```
   URL: http://localhost:5000/protected/admin
   Input: admin' OR '1'='1'--
   Result: ⛔ Request blocked by WAF
   ```

4. **Test XSS Protection**
   ```
   URL: http://localhost:5000/protected/admin
   Input: <script>alert('XSS')</script>
   Result: ⛔ Request blocked by WAF
   ```

5. **View Event Logs**
   - Check Dashboard → Event Logs
   - See detailed threat information
   - Export logs via API

### Video Demo
📹 [Watch Demo Video](https://www.youtube.com/watch?v=your-demo-video) *(Coming soon)*

## 📸 Screenshots

### WAF Dashboard
![Dashboard](screenshots/dashboard.png)
*Real-time security monitoring with threat statistics*

### Admin Login
![Login](screenshots/login.png)
*Professional glassmorphism login interface*

### Blocked IPs Management
![Blocked IPs](screenshots/blocked-ips.png)
*Dynamic IP blocking with CRUD operations*

### WAF Block Alert
![WAF Block](screenshots/waf-block.png)
*XSS/SQL injection blocked by WAF*

</details>

## 🛠️ Troubleshooting

### Common Issues

<details>
<summary><b>Port Already in Use (Error 10048)</b></summary>

**Problem**: `[Errno 10048] only one usage of each socket address is normally permitted`

**Solution**:
```powershell
# Find processes using ports 5000 or 8080
netstat -ano | findstr :5000
netstat -ano | findstr :8080

# Kill the process (replace <PID> with actual process ID)
taskkill /PID <PID> /F

# Or use the built-in port clearing script
cd scripts
clear_ports.bat
```
</details>

<details>
<summary><b>Module Not Found Error</b></summary>

**Problem**: `ModuleNotFoundError: No module named 'fastapi'`

**Solution**:
```bash
# Ensure you're in the correct directory
cd VigilEdge

# Reinstall dependencies
pip install -r waf/requirements.txt --upgrade
```
</details>

<details>
<summary><b>Database Connection Error</b></summary>

**Problem**: SQLite database not found

**Solution**:
```bash
# The database is auto-created on first run
# Ensure you're running from correct directory:
cd vulnerable-app
python app.py
```
</details>

<details>
<summary><b>Templates Not Found</b></summary>

**Problem**: `jinja2.exceptions.TemplateNotFound`

**Solution**:
```bash
# Ensure you're running from the correct directory
cd waf
python main.py

# NOT from the root VigilEdge folder
```
</details>

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add unit tests for new features
- Update documentation for API changes
- Ensure all tests pass before submitting PR

## 🔒 Security Notice

⚠️ **This project includes a vulnerable web application for testing purposes only.**

- The `vulnerable-app/` contains **intentional security vulnerabilities**
- **DO NOT** deploy the vulnerable app to production
- Use only in isolated testing environments
- The WAF component is production-ready when properly configured

## 📚 Additional Resources

- 📖 [Full Project Documentation](docs/PROJECT_REPORT_CHAPTERS.md)
- 🧪 [Testing Guide](docs/TESTING_README.md)
- 🔬 [WAF Testing Procedures](docs/WAF_TESTING_GUIDE.md)
- 🗄️ [MongoDB Integration](docs/MONGODB_README.md)
- 📁 [Project Structure Guide](PROJECT_STRUCTURE.md)

## 👥 Authors

- **Development Team** - Initial work and ongoing maintenance

## 🙏 Acknowledgments

- FastAPI framework for excellent async capabilities
- OWASP for security best practices and guidelines
- The open-source community for security research and tools

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### MIT License Summary
```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/vigiledge-waf/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/vigiledge-waf/discussions)
- **Email**: support@vigiledge.example.com

## ⭐ Star History

If you find this project useful, please consider giving it a star! ⭐

---

<div align="center">

**⚡ VigilEdge WAF - Enterprise-Grade Web Application Firewall ⚡**

Made with ❤️ by the VigilEdge Team

[Report Bug](https://github.com/yourusername/vigiledge-waf/issues) • [Request Feature](https://github.com/yourusername/vigiledge-waf/issues) • [Documentation](docs/)

</div>

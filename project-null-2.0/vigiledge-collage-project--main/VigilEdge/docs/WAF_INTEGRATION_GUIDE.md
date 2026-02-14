# 🛡️ VigilEdge WAF - Protection Integration Guide

## ✅ Integration Complete!

The VigilEdge WAF is now fully integrated with the vulnerable application to provide **real-time protection** against web attacks.

---

## 🚀 Quick Start

### Option 1: Automated Startup (Recommended)
```bash
start_waf_protection.bat
```

This will:
1. ✅ Start the vulnerable application on port 8080
2. ✅ Start the WAF on port 5000
3. ✅ Enable real-time protection

### Option 2: Manual Startup

**Terminal 1 - Start Vulnerable App:**
```bash
python vulnerable_app.py
```

**Terminal 2 - Start WAF:**
```bash
python main.py
```

---

## 🔗 Access Points

| Service | URL | Purpose |
|---------|-----|---------|
| **WAF Dashboard** | http://localhost:5000 | Monitor security events |
| **Protected App** | http://localhost:5000/protected/ | Access vulnerable app through WAF |
| **Direct Access** | http://localhost:8080 | ⚠️ Unprotected (for testing only) |
| **API Docs** | http://localhost:5000/docs | FastAPI documentation |
| **Health Check** | http://localhost:5000/test-target | Check vulnerable app status |

---

## 🎯 How It Works

```
User Request
     ↓
 WAF (Port 5000)
     ↓
 Security Check ← WAF Engine
     ↓
   Allowed? ───→ YES ──→ Forward to Vulnerable App (Port 8080)
     ↓
     NO
     ↓
   Block & Log
     ↓
 403 Response
```

### Protection Features:
- ✅ **SQL Injection Detection** - Blocks malicious database queries
- ✅ **XSS Protection** - Prevents cross-site scripting attacks  
- ✅ **Rate Limiting** - Stops DDoS attempts
- ✅ **IP Blocking** - Blacklists malicious actors
- ✅ **Real-time Monitoring** - Live dashboard updates
- ✅ **Event Logging** - Complete audit trail

---

## 🧪 Testing Protection

### 1. Normal Request (Should Pass)
```bash
# Access through WAF
http://localhost:5000/protected/
```
✅ Request forwarded to vulnerable app

### 2. SQL Injection Attack (Should Block)
```bash
# Try SQL injection
http://localhost:5000/protected/search?q=' OR '1'='1
```
🚫 WAF blocks request, returns 403

### 3. XSS Attack (Should Block)
```bash
# Try XSS injection  
http://localhost:5000/protected/search?q=<script>alert('XSS')</script>
```
🚫 WAF blocks request, logs event

### 4. View Dashboard
```bash
# Monitor attacks in real-time
http://localhost:5000/admin/dashboard
```
📊 See blocked attacks, metrics, and alerts

---

## ⚙️ Configuration

Edit `vigiledge/config.py` or set environment variables:

```python
# Vulnerable App Settings
VULNERABLE_APP_URL=http://localhost:8080
VULNERABLE_APP_ENABLED=True
VULNERABLE_APP_PROXY_PATH=/protected

# WAF Settings
HOST=127.0.0.1
PORT=5000
DEBUG=False

# Security Settings
SQL_INJECTION_PROTECTION=True
XSS_PROTECTION=True
RATE_LIMIT_ENABLED=True
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
```

---

## 📊 Dashboard Features

Access the WAF dashboard at **http://localhost:5000/admin/dashboard**

### Real-time Metrics:
- Total requests processed
- Threats blocked
- Active connections
- CPU usage
- Live threat alerts

### Monitoring Sections:
- 🎯 **Threat Detection** - SQL injection, XSS, bot detection
- 🚫 **Blocked IPs** - Blacklisted sources
- 📋 **Event Logs** - Complete request history
- 🔒 **Security Rules** - Active protection rules
- ⚙️ **Settings** - Configuration management

---

## 🔥 Testing Scenarios

### Scenario 1: SQL Injection Test
1. Start both applications
2. Access: `http://localhost:5000/protected/login`
3. Try username: `admin' OR '1'='1'--`
4. ✅ WAF should block the request
5. Check dashboard for blocked event

### Scenario 2: XSS Test
1. Access: `http://localhost:5000/protected/`
2. Try search: `<img src=x onerror=alert('XSS')>`
3. ✅ WAF should sanitize or block
4. Check dashboard for XSS detection

### Scenario 3: Rate Limiting Test
1. Send 150 requests in 60 seconds
2. ✅ After 100 requests, WAF blocks remaining
3. Check dashboard for rate limit events

---

## 🔍 Troubleshooting

### Issue: WAF shows "Protected App: OFFLINE"
**Solution:**
```bash
# Start vulnerable app first
python vulnerable_app.py

# Then start WAF
python main.py
```

### Issue: Port 5000 already in use
**Solution:**
```python
# Edit vigiledge/config.py
PORT=5001  # Change to available port
```

### Issue: Port 8080 already in use
**Solution:**
```python
# Vulnerable app auto-detects and uses 8081-8089
# Update config.py if needed:
VULNERABLE_APP_URL=http://localhost:8081
```

### Issue: WAF not blocking attacks
**Solution:**
```python
# Check security settings in config.py
SQL_INJECTION_PROTECTION=True
XSS_PROTECTION=True
```

---

## 📁 Project Structure

```
VigilEdge/
├── main.py                      # WAF application entry point
├── vulnerable_app.py            # Test target application
├── start_waf_protection.bat     # Automated startup script
├── WAF_INTEGRATION_GUIDE.md     # This file
├── vigiledge/
│   ├── config.py                # ✅ Updated with vulnerable app settings
│   ├── core/
│   │   └── waf_engine.py        # Security engine
│   └── middleware/
│       └── security_middleware.py
└── templates/
    └── enhanced_dashboard.html  # WAF dashboard
```

---

## 🎓 Learning Objectives

This integration demonstrates:
1. ✅ How WAFs protect web applications
2. ✅ Request inspection and threat detection
3. ✅ Real-time monitoring and alerting
4. ✅ Reverse proxy architecture
5. ✅ Security event logging and analysis

---

## ⚠️ Security Notice

**The vulnerable application contains intentional security flaws for educational purposes ONLY.**

- ✅ Use only in controlled test environments
- ✅ Never deploy to production
- ✅ Always use WAF protection when testing
- ✅ Review logs to understand attack patterns

---

## 🛠️ Advanced Usage

### Custom WAF Rules
Edit `config/waf_rules.yaml` to add custom patterns

### API Integration
Use the proxy programmatically:
```python
import requests

# Access through WAF
response = requests.get("http://localhost:5000/protected/api/products")
```

### WebSocket Monitoring
Connect to `ws://localhost:5000/ws` for real-time alerts

---

## 📞 Support

- 📖 Check `README.md` for general documentation
- 🔍 See `TESTING_README.md` for testing guides
- 🛡️ Review `WAF_TESTING_GUIDE.md` for WAF-specific tests

---

## ✅ Integration Checklist

- [x] WAF configuration updated
- [x] Vulnerable app URL configured
- [x] Catch-all proxy route added
- [x] Security middleware enabled
- [x] Startup health check added
- [x] Dashboard monitoring ready
- [x] Startup script created
- [x] Documentation complete

**🎉 Your WAF is now protecting the vulnerable application!**

Access the dashboard at: **http://localhost:5000**

Access protected app at: **http://localhost:5000/protected/**

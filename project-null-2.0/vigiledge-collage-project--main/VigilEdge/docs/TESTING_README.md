# 🎯 VigilEdge WAF Testing Environment

This directory contains a complete testing environment for demonstrating your VigilEdge WAF capabilities against real attacks.

## 🏗️ Architecture

```
[Attacker] → [VigilEdge WAF:5000] → [Vulnerable App:8080]
             ↓                       ↓
        [Dashboard]              [Direct Access]
```

## 📁 Files Overview

| File | Purpose |
|------|---------|
| `vulnerable_app.py` | Intentionally vulnerable web application (target) |
| `test_waf_demo.py` | Automated attack demonstration script |
| `run_testing_env.bat` | Quick start script for Windows |
| `WAF_TESTING_GUIDE.md` | Comprehensive testing documentation |

## 🚀 Quick Start

### Option 1: Automated Setup (Windows)
```cmd
run_testing_env.bat
```

### Option 2: Manual Setup
```bash
# Terminal 1 - Start vulnerable target
python vulnerable_app.py

# Terminal 2 - Start VigilEdge WAF  
python main.py

# Terminal 3 - Run attack tests
python test_waf_demo.py
```

## 🎮 Available Testing Modes

### 1. Manual Testing
- **Direct Access**: http://localhost:8080 (bypasses WAF)
- **Protected Access**: http://localhost:5000/api/v1/test/ (through WAF)
- **WAF Dashboard**: http://localhost:5000

### 2. Automated Testing
```bash
python test_waf_demo.py
```

### 3. Interactive Web Testing
Visit the vulnerable application and try these attacks:

#### SQL Injection Examples:
```
http://localhost:8080/products?id=1' OR 1=1--
http://localhost:8080/login (try: admin' OR '1'='1' --)
```

#### XSS Examples:
```
http://localhost:8080/?search=<script>alert('XSS')</script>
http://localhost:8080/contact (submit: <img src=x onerror=alert('XSS')>)
```

## 🛡️ Testing the WAF Protection

### Step 1: Test Direct Access (Should Work)
```bash
curl "http://localhost:8080/products?id=1' OR 1=1--"
```

### Step 2: Test Through WAF (Should Block)
```bash
curl "http://localhost:5000/api/v1/test/products?id=1' OR 1=1--"
```

### Step 3: Monitor Dashboard
- Open http://localhost:5000 
- Watch real-time alerts
- Check blocked IPs
- Review security events

## 📊 Expected Results

| Attack Type | Direct Access | Through WAF | Expected |
|-------------|---------------|-------------|----------|
| SQL Injection | ✅ Success | ❌ Blocked | 🛡️ Protected |
| XSS | ✅ Success | ❌ Blocked | 🛡️ Protected |
| Directory Traversal | ✅ Success | ❌ Blocked | 🛡️ Protected |
| File Upload | ✅ Success | ❌ Blocked | 🛡️ Protected |

## 🎯 Attack Scenarios Included

### 1. SQL Injection
- Basic OR conditions (`' OR 1=1--`)
- UNION SELECT attacks
- DROP TABLE attempts
- Authentication bypasses

### 2. Cross-Site Scripting (XSS)
- Script tag injection
- Event handler XSS
- SVG-based XSS
- Reflected XSS in forms

### 3. Directory Traversal
- Linux path traversal (`../../../etc/passwd`)
- Windows path traversal
- Encoded traversal attempts
- File system access attempts

### 4. File Upload Attacks
- PHP shell uploads
- Executable file uploads
- Script injection via files
- Double extension bypasses

### 5. Authentication Bypass
- Weak token guessing
- Session manipulation
- Admin panel intrusion
- Credential stuffing

## 🔍 Monitoring & Analysis

### Real-time Monitoring
- **WebSocket Alerts**: Live threat notifications
- **Dashboard Metrics**: Request counts, block rates
- **IP Tracking**: Geographic threat analysis

### Logging Analysis
```bash
# View security events
tail -f logs/vigiledge.log

# Search for specific attacks
grep "sql_injection" logs/vigiledge.log
grep "xss" logs/vigiledge.log
```

### Database Inspection
```bash
# Check vulnerable app database
sqlite3 vulnerable.db
.tables
SELECT * FROM users;
```

## 🚨 Security Warnings

**⚠️ IMPORTANT: For Testing Only!**

- Never use `vulnerable_app.py` in production
- Only run on isolated test networks
- Delete vulnerable app after testing
- Monitor for real attacks during demos
- Keep WAF logs for analysis

## 🎨 Customization

### Adding Custom Attacks
Edit `test_waf_demo.py` to add new attack scenarios:

```python
async def test_custom_attack(self):
    """Test custom attack patterns"""
    custom_tests = [
        ("/endpoint?param=malicious_payload", "payload", "Custom Attack"),
    ]
    
    for endpoint, payload, attack_type in custom_tests:
        await self.test_direct_vs_waf(endpoint, payload, attack_type)
```

### Modifying WAF Rules
Edit `config/waf_rules.yaml` to adjust detection patterns:

```yaml
custom_attack:
  enabled: true
  rules:
    - id: "CUSTOM_001"
      name: "Custom Attack Pattern"
      pattern: "malicious_pattern"
      severity: "high"
```

## 📈 Performance Testing

### Load Testing
```bash
# Install Apache Bench
# apt-get install apache2-utils  # Linux
# brew install apache-bench      # macOS

# Test normal traffic
ab -n 1000 -c 10 http://localhost:5000/api/v1/test/

# Test attack traffic  
ab -n 100 -c 5 "http://localhost:5000/api/v1/test/products?id=1' OR 1=1--"
```

### Rate Limiting Tests
```bash
# Rapid requests to test rate limiting
for i in {1..50}; do curl "http://localhost:5000/api/v1/test/" & done
```

## 🎓 Educational Use

This testing environment is perfect for:

- **Security Training**: Hands-on WAF demonstration
- **Academic Projects**: Cybersecurity coursework  
- **Penetration Testing**: Safe attack simulation
- **Product Demos**: Showcasing WAF capabilities
- **Red Team Exercises**: Attack/defense scenarios

## 🛠️ Troubleshooting

### Common Issues

**Vulnerable app won't start:**
```bash
# Check if port 8080 is in use
netstat -an | grep 8080
# Kill process if needed
taskkill /f /pid <pid>  # Windows
kill -9 <pid>           # Linux/macOS
```

**WAF not blocking attacks:**
- Check WAF configuration in `vigiledge/config.py`
- Verify security rules in `config/waf_rules.yaml`
- Review middleware setup in `main.py`

**Connection refused errors:**
- Ensure both applications are running
- Check firewall settings
- Verify port availability

## 🎯 Success Criteria

Your WAF demonstration is successful when:

- ✅ Direct attacks on vulnerable app succeed
- ✅ Same attacks through WAF are blocked  
- ✅ Dashboard shows real-time security alerts
- ✅ Security events are properly logged
- ✅ Legitimate traffic flows normally
- ✅ Performance remains acceptable under load

## 📞 Demo Script

Use this script for presentations:

1. **Show vulnerable app**: "This is what attackers target"
2. **Demonstrate attacks**: "These attacks work on unprotected sites"
3. **Enable WAF**: "Now let's add VigilEdge WAF protection"
4. **Show blocking**: "Same attacks are now blocked"
5. **Display dashboard**: "Real-time monitoring and alerting"
6. **Review logs**: "Complete audit trail for compliance"

---

**🛡️ Protect. Monitor. Defend. - VigilEdge WAF**

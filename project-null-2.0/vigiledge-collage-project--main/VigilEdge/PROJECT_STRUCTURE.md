# VigilEdge Project Structure

## 📁 Reorganized Project Layout

This document describes the professional folder structure implemented for the VigilEdge WAF project.

## 🏗️ Directory Structure

```
VigilEdge/
│
├── waf/                                  # WAF Application Directory
│   ├── main.py                          # WAF entry point and dashboard
│   ├── requirements.txt                 # Python dependencies
│   │
│   ├── vigiledge/                       # Core WAF Package
│   │   ├── __init__.py
│   │   ├── config.py                    # Configuration management
│   │   │
│   │   ├── core/                        # Security Engines
│   │   │   ├── waf_engine.py           # Main threat detection engine
│   │   │   └── security_manager.py     # Security management
│   │   │
│   │   ├── middleware/                  # Request Processing
│   │   │   └── security_middleware.py  # Security filtering middleware
│   │   │
│   │   ├── api/                         # REST API Endpoints
│   │   │   └── routes.py               # API route definitions
│   │   │
│   │   └── utils/                       # Utilities
│   │       └── logger.py               # Logging utilities
│   │
│   ├── config/                          # Configuration Files
│   │   └── waf_rules.yaml              # Security rule definitions
│   │
│   ├── templates/                       # Dashboard HTML Templates
│   │   ├── enhanced_dashboard.html
│   │   ├── analytics.html
│   │   ├── blocked_ips.html
│   │   ├── event_logs.html
│   │   └── ...
│   │
│   └── static/                          # Static Assets
│       ├── css/
│       │   └── enhanced-dashboard.css
│       └── js/
│           └── enhanced-dashboard.js
│
├── vulnerable-app/                      # Vulnerable Test Application
│   ├── app.py                          # Main application (renamed from vulnerable_app.py)
│   ├── vulnerable.db                   # SQLite database
│   ├── vulnerable_backup.db            # Database backup
│   ├── vulnerable_app_mongodb.py       # MongoDB variant
│   ├── product_catalog.py             # Product catalog utilities
│   ├── vulnshop_demo.py               # Demo scripts
│   └── home_fixed.py                  # Home page variant
│
├── scripts/                             # Automation Scripts
│   ├── start_both.bat                  # Start WAF + Vulnerable App
│   ├── setup.bat                       # Environment setup
│   ├── setup.ps1                       # PowerShell setup script
│   ├── launch.bat                      # Launch script
│   ├── launch.ps1                      # PowerShell launch script
│   ├── launch_mongodb.bat              # MongoDB launcher
│   ├── launch_mongodb.ps1              # PowerShell MongoDB launcher
│   ├── clear_ports.bat                 # Port cleanup utility
│   ├── demo.bat                        # Demo script
│   ├── run_testing_env.bat             # Testing environment
│   ├── setup.py                        # Python setup script
│   ├── setup_mongodb.py                # MongoDB setup script
│   ├── start_testing_environment.py    # Testing environment starter
│   ├── check_db.py                     # Database checker
│   └── check_events.py                 # Event log checker
│
├── docs/                                # Documentation
│   ├── PROJECT_REPORT_CHAPTERS.md      # Main project report
│   ├── TESTING_README.md               # Testing documentation
│   ├── WAF_TESTING_GUIDE.md            # WAF testing procedures
│   ├── MONGODB_README.md               # MongoDB integration guide
│   ├── WAF_INTEGRATION_GUIDE.md        # Integration instructions
│   └── WAF_INTEGRATION_COMPLETE.md     # Completion checklist
│
├── tests/                               # Test Suite
│   ├── test_waf.py                     # WAF unit tests
│   ├── test_auth.py                    # Authentication tests
│   ├── test_login.py                   # Login tests
│   ├── test_waf_demo.py                # WAF demo tests
│   ├── test_navigation.html            # Navigation test page
│   └── quick_test.py                   # Quick test utility
│
├── logs/                                # Log Files
│   └── vigiledge.log                   # WAF logs
│
├── README.md                            # Main README (root level)
├── PROJECT_STRUCTURE.md                 # This file
└── LICENSE                              # Project license

```

## 🚀 Quick Start Commands

### Start Both Applications
```bash
# Windows - Recommended
scripts\start_both.bat

# Manually start WAF
cd waf
python main.py

# Manually start Vulnerable App (in another terminal)
cd vulnerable-app
python app.py
```

### Access Points
- WAF Dashboard: http://localhost:5000/dashboard
- Protected App: http://localhost:5000/protected/
- Admin Login: http://localhost:5000/protected/admin
- Direct Vulnerable App: http://localhost:8080/ (bypasses WAF)

## 🔧 Key Changes from Previous Structure

### Before (Flat Structure)
```
VigilEdge/
├── main.py
├── vulnerable_app.py
├── vigiledge/
├── config/
├── templates/
├── static/
├── test_*.py
├── setup.bat
├── launch.bat
├── README.md
├── TESTING_README.md
└── ... (48+ files mixed together)
```

### After (Organized Structure)
```
VigilEdge/
├── waf/              # All WAF files isolated
├── vulnerable-app/   # All test app files isolated
├── scripts/          # All automation scripts centralized
├── docs/             # All documentation in one place
└── tests/            # All test files organized
```

## 📝 Path Updates Made

### 1. WAF Application (`waf/main.py`)
- **Templates**: Already using `current_dir` with `os.path.join()`
- **Static files**: Already using `current_dir` with `os.path.join()`
- ✅ No changes needed - paths are relative to script location

### 2. Vulnerable App (`vulnerable-app/app.py`)
- **Added**: `BASE_DIR = os.path.dirname(os.path.abspath(__file__))`
- **Database**: Changed from `'vulnerable.db'` to `os.path.join(BASE_DIR, 'vulnerable.db')`
- **Templates**: Updated to reference WAF templates: `os.path.join(os.path.dirname(BASE_DIR), "waf", "templates")`
- ✅ All 11 database connections updated

### 3. Startup Scripts (`scripts/start_both.bat`)
- **Changed working directory**: `cd /d "%~dp0\.."`
- **WAF command**: `cd waf && python main.py`
- **Vulnerable App command**: `cd vulnerable-app && python app.py`
- ✅ Scripts now work from scripts/ folder

### 4. Requirements File
- **Moved**: `requirements.txt` → `waf/requirements.txt`
- **Updated**: README.md references to reflect new location

## 🎯 Benefits of New Structure

### 1. **Separation of Concerns**
- WAF and vulnerable app are completely isolated
- No mixing of test code with production WAF code
- Clear boundaries between components

### 2. **Improved Maintainability**
- Easy to locate specific files (all scripts in scripts/, all docs in docs/)
- Reduced clutter in root directory
- Professional project appearance

### 3. **Better Scalability**
- Easy to add new scripts without cluttering root
- Documentation organized in single location
- Test files centralized for CI/CD integration

### 4. **Enterprise Standards**
- Follows industry best practices for project organization
- Clear folder hierarchy that scales to large teams
- Separates deployment artifacts (scripts) from source code

## ✅ Functionality Verification

### WAF Tests
```bash
# Start WAF
cd waf
python main.py
# ✅ Expected: WAF starts on port 5000
# ✅ Dashboard accessible at http://localhost:5000/dashboard
```

### Vulnerable App Tests
```bash
# Start Vulnerable App
cd vulnerable-app
python app.py
# ✅ Expected: App starts on port 8080
# ✅ Database loads successfully
# ✅ Templates render correctly
```

### Integration Tests
```bash
# Access protected app through WAF
http://localhost:5000/protected/
# ✅ Expected: Proxies to vulnerable app
# ✅ WAF monitoring active
# ✅ Threat detection working
```

### Security Tests
```bash
# Test XSS Protection
# Input: <script>alert('XSS')</script>
# ✅ Expected: Blocked by WAF

# Test SQL Injection
# Input: ' OR '1'='1
# ✅ Expected: Blocked by WAF

# Test Session Auth
# Copy admin URL to new browser
# ✅ Expected: Redirects to login (session required)
```

## 🔒 Security Note

All paths use absolute resolution from `BASE_DIR` or `current_dir`:
- ✅ No hardcoded paths
- ✅ Works from any working directory
- ✅ Cross-platform compatible (uses `os.path.join()`)
- ✅ Secure against path traversal in file operations

## 📚 Related Documentation

- `README.md` - Main project documentation
- `docs/PROJECT_REPORT_CHAPTERS.md` - Detailed project report
- `docs/TESTING_README.md` - Testing procedures
- `docs/WAF_TESTING_GUIDE.md` - WAF-specific testing guide

---

**Last Updated**: December 2024  
**Organization Version**: 2.0  
**Status**: ✅ Fully functional and tested

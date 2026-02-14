# VulnShop MongoDB Edition

A vulnerable web application with MongoDB backend for testing Web Application Firewalls (WAF) and learning about NoSQL injection vulnerabilities.

## 🚨 IMPORTANT WARNING

**This application contains intentional security vulnerabilities and should NEVER be used in production environments. It is designed exclusively for educational purposes and security testing.**

## 🍃 MongoDB Features

This MongoDB edition of VulnShop includes:

- **NoSQL Injection Vulnerabilities**: Test MongoDB-specific injection attacks
- **Authentication Bypass**: Vulnerable login system using MongoDB queries
- **Data Extraction**: Unprotected database queries allowing data enumeration
- **JavaScript Injection**: MongoDB `$where` operator vulnerabilities
- **Operator Injection**: Direct injection of MongoDB operators

## 📋 Prerequisites

1. **Python 3.7+** installed
2. **MongoDB Community Server** running on `localhost:27017`
3. **Python packages**: `pymongo`, `motor`, `fastapi`, `uvicorn`

## 🚀 Quick Start

### Option 1: Using Launch Scripts (Recommended)

**Windows (PowerShell):**
```powershell
.\launch_mongodb.ps1
```

**Windows (Command Prompt):**
```cmd
launch_mongodb.bat
```

### Option 2: Manual Setup

1. **Start MongoDB:**
   ```bash
   mongod --port 27017
   ```

2. **Install Python dependencies:**
   ```bash
   pip install pymongo motor fastapi uvicorn
   ```

3. **Initialize database:**
   ```bash
   python setup_mongodb.py
   ```

4. **Run the application:**
   ```bash
   python vulnerable_app_mongodb.py
   ```

## 🌐 Access URLs

- **Main Application**: http://localhost:8082
- **Admin Panel**: http://localhost:8082/admin
- **MongoDB Info**: http://localhost:8082/mongo-info
- **Health Check**: http://localhost:8082/health

## 🎯 Vulnerability Testing

### Test Accounts

| Username | Password | Role |
|----------|----------|------|
| admin    | admin123 | Administrator |
| user     | password | Regular User |
| guest    | guest    | Guest User |

### NoSQL Injection Examples

1. **Authentication Bypass** - Login form:
   ```json
   Username: {"$ne": null}
   Password: {"$ne": null}
   ```

2. **MongoDB Operator Injection** - Products search:
   ```
   /products?search={"$where": "this.price > 500"}
   ```

3. **Regex Injection** - Data extraction:
   ```
   /products?filter={"$regex": ".*"}
   ```

4. **JavaScript Injection** - Using $where operator:
   ```json
   {"$where": "function() { return this.username.length > 0; }"}
   ```

### Attack Vectors

| Endpoint | Vulnerability | Example Payload |
|----------|---------------|-----------------|
| `/login` | Authentication Bypass | `{"$ne": null}` |
| `/products` | NoSQL Injection | `{"$where": "1==1"}` |
| `/login` | Operator Injection | `{"$gt": ""}` |
| `/products` | Regex Injection | `{"$regex": ".*"}` |

## 🗃️ Database Structure

### Collections

1. **users** - User accounts and credentials
   ```javascript
   {
     "_id": ObjectId,
     "username": String,
     "password": String,  // Plain text (vulnerable!)
     "email": String,
     "is_admin": Boolean,
     "created_at": Date,
     "profile": {
       "first_name": String,
       "last_name": String,
       "phone": String
     }
   }
   ```

2. **products** - E-commerce product catalog
   ```javascript
   {
     "_id": ObjectId,
     "name": String,
     "price": Number,
     "description": String,
     "category": String,
     "stock": Number,
     "brand": String,
     "rating": Number,
     "created_at": Date
   }
   ```

3. **orders** - Customer orders (with indexes)

## 🔧 Configuration

### MongoDB Settings

- **URL**: `mongodb://localhost:27017/`
- **Database**: `vulnshop`
- **Connection Timeout**: 5 seconds

### Application Settings

- **Default Port**: 8082 (auto-detects available ports)
- **Host**: 127.0.0.1 (localhost only)
- **Debug Mode**: Enabled for vulnerability demonstration

## 🛡️ WAF Testing Integration

This application works with the VigilEdge WAF system:

1. Start VigilEdge WAF on port 5000
2. Start VulnShop MongoDB on port 8082
3. Configure WAF to monitor traffic to VulnShop
4. Test NoSQL injection attacks through the WAF

### Expected WAF Detections

- NoSQL injection patterns
- Authentication bypass attempts
- Suspicious MongoDB operators
- JavaScript injection in queries
- Regex-based data extraction

## 🧪 Testing Scripts

### Database Setup Script
```bash
python setup_mongodb.py
```

### Injection Testing
```bash
python setup_mongodb.py --test
```

### Health Check
```bash
curl http://localhost:8082/health
```

## 📊 Monitoring

### Database Statistics
Access real-time MongoDB statistics at:
```
http://localhost:8082/mongo-info
```

### Application Logs
Monitor the console output for:
- MongoDB queries being executed
- Injection attempts
- Database connection status
- Security vulnerabilities triggered

## 🔍 Troubleshooting

### MongoDB Connection Issues

1. **Check if MongoDB is running:**
   ```bash
   mongod --version
   ```

2. **Start MongoDB service:**
   ```bash
   # Windows
   net start MongoDB
   
   # macOS
   brew services start mongodb-community
   
   # Linux
   sudo systemctl start mongod
   ```

3. **Check MongoDB port:**
   ```bash
   netstat -an | findstr :27017
   ```

### Package Installation Issues

1. **Install MongoDB drivers:**
   ```bash
   pip install pymongo motor
   ```

2. **Install web framework:**
   ```bash
   pip install fastapi uvicorn
   ```

### Port Conflicts

The application automatically detects available ports starting from 8082. If all ports 8082-8091 are in use:

1. Close applications using these ports
2. Or manually specify a port in the code

## 📚 Educational Resources

### NoSQL Injection Learning

- **OWASP NoSQL Injection**: Understanding NoSQL vulnerabilities
- **MongoDB Security**: Best practices for MongoDB security
- **WAF Evasion**: Techniques for bypassing web application firewalls

### Related Vulnerabilities

- Authentication bypass using MongoDB operators
- Data extraction through regex injection
- JavaScript injection in NoSQL databases
- Privilege escalation via operator injection

## ⚠️ Security Disclaimer

This application is intentionally vulnerable and contains:

- **Plain text passwords** stored in database
- **No input validation** on user inputs
- **Direct database query construction** from user input
- **No authentication on sensitive endpoints**
- **Verbose error messages** revealing system information

**DO NOT DEPLOY THIS APPLICATION IN ANY PRODUCTION ENVIRONMENT**

## 📝 License

This educational tool is provided as-is for learning purposes only. Use responsibly and only in authorized testing environments.

---

**Happy (Ethical) Hacking! 🔐**

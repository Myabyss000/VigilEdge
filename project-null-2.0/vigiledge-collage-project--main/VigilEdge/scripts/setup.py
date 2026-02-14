#!/usr/bin/env python3
"""
VigilEdge WAF Setup Script
Installs dependencies and initializes the WAF system
"""

import os
import sys
import subprocess
import platform
from pathlib import Path


def print_banner():
    """Print setup banner"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                     VigilEdge WAF Setup                     ║
║              Advanced Web Application Firewall              ║
║                        Version 1.0.0                        ║
╚══════════════════════════════════════════════════════════════╝
    """)


def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        sys.exit(1)
    
    print(f"✅ Python version: {sys.version.split()[0]}")


def install_dependencies():
    """Install Python dependencies"""
    print("\n📦 Installing dependencies...")
    
    try:
        # Upgrade pip first
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        
        # Install requirements
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        
        print("✅ Dependencies installed successfully")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        print("\n💡 Try installing manually:")
        print("   pip install -r requirements.txt")
        return False
    
    return True


def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    
    directories = [
        "logs",
        "data",
        "config",
        "static",
        "templates"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"   Created: {directory}/")
    
    print("✅ Directories created")


def setup_environment():
    """Setup environment configuration"""
    print("\n⚙️  Setting up environment...")
    
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if not env_file.exists() and env_example.exists():
        # Copy example to .env
        with open(env_example, 'r') as src, open(env_file, 'w') as dst:
            dst.write(src.read())
        print("✅ Environment file created from .env.example")
    elif env_file.exists():
        print("✅ Environment file already exists")
    else:
        print("⚠️  No environment template found")


def initialize_database():
    """Initialize database (if using database features)"""
    print("\n🗄️  Initializing database...")
    
    try:
        # Create database file if using SQLite
        db_path = Path("vigiledge.db")
        if not db_path.exists():
            db_path.touch()
        
        print("✅ Database initialized")
        
    except Exception as e:
        print(f"⚠️  Database initialization warning: {e}")


def run_tests():
    """Run basic tests to verify installation"""
    print("\n🧪 Running basic tests...")
    
    try:
        # Test imports
        import fastapi
        import uvicorn
        import pydantic
        print("✅ Core dependencies imported successfully")
        
        # Test application creation
        from vigiledge.config import get_settings
        settings = get_settings()
        print("✅ Configuration loaded successfully")
        
        from vigiledge.core.waf_engine import WAFEngine
        waf = WAFEngine()
        print("✅ WAF engine initialized successfully")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Test error: {e}")
        return False


def print_next_steps():
    """Print next steps for the user"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                      Setup Complete! 🎉                     ║
╚══════════════════════════════════════════════════════════════╝

🚀 Next Steps:

1. Review and update configuration:
   Edit .env file to customize your settings

2. Start the WAF:
   python main.py

3. Access the dashboard:
   http://localhost:5000

4. View API documentation:
   http://localhost:5000/docs

5. Test the WAF:
   Try accessing: http://localhost:5000/api/v1/test/trigger-sql-injection

📖 Documentation:
   - README.md - Complete documentation
   - /docs endpoint - Interactive API docs
   - logs/ directory - Application logs

🛡️  Security Features Enabled:
   ✅ SQL Injection Protection
   ✅ XSS Protection  
   ✅ Rate Limiting
   ✅ IP Blocking
   ✅ Bot Detection
   ✅ Real-time Monitoring

⚠️  Production Notes:
   - Change SECRET_KEY in .env
   - Set DEBUG=false
   - Configure proper database
   - Set up SSL/TLS
   - Review security settings

Happy protecting! 🛡️
    """)


def main():
    """Main setup function"""
    print_banner()
    
    # Check system requirements
    check_python_version()
    
    # Install dependencies
    if not install_dependencies():
        print("\n❌ Setup failed at dependency installation")
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Setup environment
    setup_environment()
    
    # Initialize database
    initialize_database()
    
    # Run tests
    if not run_tests():
        print("\n⚠️  Setup completed with warnings")
        print("   Some features may not work correctly")
    else:
        print("\n✅ All tests passed!")
    
    # Print next steps
    print_next_steps()


if __name__ == "__main__":
    main()

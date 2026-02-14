#!/usr/bin/env python3
"""
Smart Testing Environment Starter
Automatically finds available ports and configures the WAF proxy
"""

import subprocess
import socket
import time
import os
import sys
import signal
from pathlib import Path


def find_available_port(start_port=8080, max_attempts=10):
    """Find an available port starting from start_port"""
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    return None


def check_port_in_use(port):
    """Check if a port is in use"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', port))
            return False
    except OSError:
        return True


def kill_process_on_port(port):
    """Kill process using the specified port (Windows)"""
    try:
        # Find process using the port
        result = subprocess.run(
            f'netstat -aon | findstr :{port}',
            shell=True,
            capture_output=True,
            text=True
        )
        
        if result.stdout:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if f':{port} ' in line and 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        pid = parts[-1]
                        print(f"🔪 Killing process {pid} using port {port}")
                        subprocess.run(f'taskkill /f /pid {pid}', shell=True, capture_output=True)
                        time.sleep(1)
                        return True
        return False
    except Exception as e:
        print(f"⚠️  Error killing process on port {port}: {e}")
        return False


def update_waf_proxy_config(target_port):
    """Update WAF proxy configuration to use the correct target port"""
    main_py_path = Path("main.py")
    if not main_py_path.exists():
        print("❌ main.py not found!")
        return False
    
    try:
        # Read the current main.py
        with open(main_py_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Update the target URL in proxy functions
        old_url = 'f"http://localhost:8080/{path}"'
        new_url = f'f"http://localhost:{target_port}/{{path}}"'
        
        if old_url in content:
            content = content.replace(old_url, new_url)
            
            # Also update health check URL
            old_health = '"http://localhost:8080/health"'
            new_health = f'"http://localhost:{target_port}/health"'
            content = content.replace(old_health, new_health)
            
            # Write back the updated content
            with open(main_py_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print(f"✅ Updated WAF proxy to target port {target_port}")
            return True
        else:
            print("ℹ️  WAF proxy configuration already up to date")
            return True
            
    except Exception as e:
        print(f"❌ Error updating WAF config: {e}")
        return False


def start_vulnerable_app():
    """Start the vulnerable application"""
    print("\n🎯 Starting Vulnerable Test Application...")
    
    # Check if port 8080 is available
    if check_port_in_use(8080):
        print(f"⚠️  Port 8080 is in use. Looking for alternative...")
        
        # Try to kill the process using port 8080
        if kill_process_on_port(8080):
            print("✅ Freed up port 8080")
            time.sleep(2)
    
    # Find available port
    target_port = find_available_port(8080, 10)
    if target_port is None:
        print("❌ No available ports found (8080-8089)")
        return None, None
    
    if target_port != 8080:
        print(f"ℹ️  Using port {target_port} instead of 8080")
        update_waf_proxy_config(target_port)
    
    # Start the vulnerable app
    try:
        process = subprocess.Popen(
            [sys.executable, "vulnerable_app.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Wait for startup
        print("⏳ Waiting for vulnerable app to start...")
        time.sleep(3)
        
        # Check if process is still running
        if process.poll() is None:
            print(f"✅ Vulnerable app started on http://localhost:{target_port}")
            return process, target_port
        else:
            print("❌ Vulnerable app failed to start")
            return None, None
            
    except Exception as e:
        print(f"❌ Error starting vulnerable app: {e}")
        return None, None


def start_waf():
    """Start the WAF"""
    print("\n🛡️  Starting VigilEdge WAF...")
    
    try:
        process = subprocess.Popen(
            [sys.executable, "main.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        print("⏳ Waiting for WAF to start...")
        time.sleep(5)
        
        if process.poll() is None:
            print("✅ VigilEdge WAF started on http://localhost:5000")
            return process
        else:
            print("❌ WAF failed to start")
            return None
            
    except Exception as e:
        print(f"❌ Error starting WAF: {e}")
        return None


def main():
    """Main function"""
    print("🚀 VigilEdge WAF Testing Environment Launcher")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not Path("main.py").exists() or not Path("vulnerable_app.py").exists():
        print("❌ Please run this script from the VigilEdge directory")
        print("   Required files: main.py, vulnerable_app.py")
        return
    
    processes = []
    
    try:
        # Start vulnerable app
        vuln_process, target_port = start_vulnerable_app()
        if vuln_process:
            processes.append(("Vulnerable App", vuln_process))
        else:
            print("❌ Cannot continue without vulnerable app")
            return
        
        # Start WAF
        waf_process = start_waf()
        if waf_process:
            processes.append(("VigilEdge WAF", waf_process))
        else:
            print("❌ Cannot continue without WAF")
            return
        
        print("\n" + "=" * 50)
        print("🎉 Testing Environment Ready!")
        print("=" * 50)
        print(f"📊 WAF Dashboard:     http://localhost:5000")
        print(f"🎯 Vulnerable Target: http://localhost:{target_port}")
        print(f"🛡️  Protected Access:  http://localhost:5000/api/v1/test/")
        print(f"📖 API Documentation: http://localhost:5000/docs")
        print("\n💡 To test attacks:")
        print("   1. Try direct access to vulnerable app (attacks work)")
        print("   2. Try same attacks through WAF (attacks blocked)")
        print("   3. Monitor the WAF dashboard for real-time alerts")
        print("\n🧪 Run automated tests:")
        print("   python test_waf_demo.py")
        print("\n⚠️  Press Ctrl+C to stop all services")
        print("=" * 50)
        
        # Keep running until interrupted
        try:
            while True:
                time.sleep(1)
                # Check if processes are still running
                for name, process in processes:
                    if process.poll() is not None:
                        print(f"⚠️  {name} has stopped unexpectedly")
        except KeyboardInterrupt:
            print("\n🛑 Shutting down testing environment...")
            
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        
    finally:
        # Clean up processes
        for name, process in processes:
            if process.poll() is None:
                print(f"🔄 Stopping {name}...")
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                except Exception as e:
                    print(f"⚠️  Error stopping {name}: {e}")
        
        print("✅ All services stopped. Testing environment shut down.")


if __name__ == "__main__":
    main()

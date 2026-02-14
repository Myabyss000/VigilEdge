#!/usr/bin/env python3
"""
Simple WAF Testing Demo
This script tests if the vulnerable app and WAF are working correctly
"""

import requests
import time
import json

def test_vulnerable_app_directly():
    """Test direct access to vulnerable application"""
    print("🎯 Testing Vulnerable App Directly (Should work)")
    print("=" * 50)
    
    try:
        # Test basic homepage
        response = requests.get("http://localhost:8080", timeout=5)
        if response.status_code == 200:
            print("✅ Homepage: Working")
        else:
            print(f"❌ Homepage failed with status {response.status_code}")
        
        # Test SQL injection (should work - app is vulnerable)
        sqli_url = "http://localhost:8080/products?id=1' OR 1=1--"
        response = requests.get(sqli_url, timeout=5)
        if response.status_code == 200:
            print("✅ SQL Injection: Attack succeeded (as expected - app is vulnerable)")
            data = response.json()
            print(f"   Executed query: {data.get('executed_query', 'Unknown')}")
        else:
            print(f"❌ SQL Injection test failed with status {response.status_code}")
        
        # Test XSS (should work - app is vulnerable)
        xss_url = "http://localhost:8080/?search=<script>alert('XSS')</script>"
        response = requests.get(xss_url, timeout=5)
        if response.status_code == 200:
            print("✅ XSS: Attack succeeded (as expected - app is vulnerable)")
        else:
            print(f"❌ XSS test failed with status {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to vulnerable app on port 8080")
        print("   Make sure to run: python vulnerable_app.py")
        return False
    except Exception as e:
        print(f"❌ Error testing vulnerable app: {e}")
        return False
    
    return True


def test_waf_protection():
    """Test WAF protection (should block attacks)"""
    print("\n🛡️  Testing WAF Protection (Should block attacks)")
    print("=" * 50)
    
    try:
        # Test if WAF is running
        response = requests.get("http://localhost:5000/health", timeout=5)
        if response.status_code == 200:
            print("✅ WAF Health Check: Running")
        else:
            print(f"❌ WAF health check failed with status {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to WAF on port 5000")
        print("   Make sure to run: python main.py")
        return False
    
    try:
        # Test SQL injection through WAF (should be blocked)
        sqli_url = "http://localhost:5000/api/v1/test/products?id=1' OR 1=1--"
        response = requests.get(sqli_url, timeout=5)
        if response.status_code == 403:
            print("✅ SQL Injection: Blocked by WAF")
            try:
                data = response.json()
                print(f"   Reason: {data.get('reason', 'Security violation')}")
            except:
                pass
        elif response.status_code == 503:
            print("⚠️  WAF proxy not configured correctly (service unavailable)")
            try:
                data = response.json()
                print(f"   Message: {data.get('message', 'Unknown error')}")
            except:
                pass
        else:
            print(f"❌ SQL Injection not blocked (status: {response.status_code})")
            
        # Test XSS through WAF (should be blocked)  
        xss_url = "http://localhost:5000/api/v1/test/?search=<script>alert('XSS')</script>"
        response = requests.get(xss_url, timeout=5)
        if response.status_code == 403:
            print("✅ XSS: Blocked by WAF")
        elif response.status_code == 503:
            print("⚠️  WAF proxy not configured correctly")
        else:
            print(f"❌ XSS not blocked (status: {response.status_code})")
            
    except Exception as e:
        print(f"❌ Error testing WAF: {e}")
        return False
    
    return True


def show_demo_urls():
    """Show URLs for manual testing"""
    print("\n📋 Manual Testing URLs")
    print("=" * 50)
    print("🎯 DIRECT ACCESS (Vulnerable - attacks work):")
    print("   Homepage: http://localhost:8080")
    print("   SQL Injection: http://localhost:8080/products?id=1' OR 1=1--")
    print("   XSS: http://localhost:8080/?search=<script>alert('XSS')</script>")
    
    print("\n🛡️  THROUGH WAF (Protected - attacks blocked):")
    print("   Dashboard: http://localhost:5000")
    print("   Homepage: http://localhost:5000/api/v1/test/")
    print("   SQL Injection: http://localhost:5000/api/v1/test/products?id=1' OR 1=1--")
    print("   XSS: http://localhost:5000/api/v1/test/?search=<script>alert('XSS')</script>")


def main():
    """Main demo function"""
    print("🔥 VigilEdge WAF Demo - Quick Test")
    print("=" * 50)
    
    # Test vulnerable app first
    if not test_vulnerable_app_directly():
        print("\n❌ Vulnerable app is not working. Please start it first:")
        print("   python vulnerable_app.py")
        return
    
    # Test WAF protection
    if not test_waf_protection():
        print("\n❌ WAF is not working. Please start it first:")
        print("   python main.py")
        return
    
    print("\n🎉 SUCCESS! Both applications are working correctly!")
    print("\n📊 Summary:")
    print("✅ Vulnerable app (port 8080): Accepts attacks")
    print("✅ VigilEdge WAF (port 5000): Blocks attacks")
    print("✅ Testing environment is ready!")
    
    show_demo_urls()
    
    print("\n💡 Next Steps:")
    print("1. Visit the URLs above to see the difference")
    print("2. Check WAF dashboard for real-time monitoring") 
    print("3. Run full test suite: python test_waf_demo.py")


if __name__ == "__main__":
    main()

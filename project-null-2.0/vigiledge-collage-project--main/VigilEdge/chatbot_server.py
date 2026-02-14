"""
VigilEdge Chatbot Server with WAF API Integration
Connects to WAF API endpoints for real-time data access (READ-ONLY)
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os

app = Flask(__name__)
CORS(app)  # Allow requests from WAF frontend

# WAF API Base URL
WAF_API_URL = "http://localhost:5000/api/waf"

def get_waf_data():
    """Fetch comprehensive WAF data from API endpoints"""
    try:
        data = {
            "stats": {},
            "threats": [],
            "blocked_ips": [],
            "security_rules": [],
            "events": [],
            "network_monitor": {},
            "threat_summary": {}
        }
        
        # Fetch stats
        try:
            resp = requests.get(f"{WAF_API_URL}/stats", timeout=2)
            if resp.status_code == 200:
                data["stats"] = resp.json().get("data", {})
        except:
            pass
        
        # Fetch recent threats
        try:
            resp = requests.get(f"{WAF_API_URL}/threats", timeout=2)
            if resp.status_code == 200:
                data["threats"] = resp.json().get("data", [])
        except:
            pass
        
        # Fetch blocked IPs
        try:
            resp = requests.get(f"{WAF_API_URL}/blocked_ips", timeout=2)
            if resp.status_code == 200:
                data["blocked_ips"] = resp.json().get("data", {}).get("blocked_ips", [])
        except:
            pass
        
        # Fetch security rules
        try:
            resp = requests.get(f"{WAF_API_URL}/security_rules", timeout=2)
            if resp.status_code == 200:
                data["security_rules"] = resp.json().get("data", {}).get("rules", [])
        except:
            pass
        
        # Fetch threat summary
        try:
            resp = requests.get(f"{WAF_API_URL}/threat_summary", timeout=2)
            if resp.status_code == 200:
                data["threat_summary"] = resp.json().get("data", {})
        except:
            pass
        
        # Fetch network monitor
        try:
            resp = requests.get(f"{WAF_API_URL}/network_monitor", timeout=2)
            if resp.status_code == 200:
                data["network_monitor"] = resp.json().get("data", {})
        except:
            pass
        
        return data
    except Exception as e:
        print(f"Error fetching WAF data: {e}")
        return None

def build_context_message(waf_data):
    """Build comprehensive context message for AI"""
    if not waf_data:
        return "Error: Cannot access WAF data."
    
    stats = waf_data.get("stats", {})
    threats = waf_data.get("threats", [])[:5]  # Top 5 recent threats
    threat_summary = waf_data.get("threat_summary", {})
    threat_breakdown = threat_summary.get("threat_breakdown", [])
    network = waf_data.get("network_monitor", {})
    blocked_ips = waf_data.get("blocked_ips", [])
    
    context = f"""You are VigilEdge AI, a cybersecurity expert assistant. Your job is to help users understand their WAF (Web Application Firewall) security data.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 LIVE FIREWALL DATA:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

System Statistics (Last 24 Hours):
• Threats Blocked: {stats.get('threats_blocked', 0)}
• Active Scans: {stats.get('active_scans', 0)}
• Requests Allowed: {stats.get('requests_allowed', 0)}
• Total Events: {stats.get('total_events', 0)}
• Unique IPs Detected: {stats.get('unique_ips', 0)}

Attack Types Detected:
{chr(10).join([f"• {t.get('threat_type', 'Unknown')}: {t.get('count', 0)} attempts" for t in threat_breakdown[:5]]) if threat_breakdown else "• No attacks detected"}

Blocked IP Addresses:
{chr(10).join([f"• {ip.get('ip', 'Unknown')} - Blocked {ip.get('block_count', 0)} times" for ip in blocked_ips[:10]]) if blocked_ips else "• No IPs have been blocked"}

Active Network Connections:
• Currently Active: {network.get('total_active', 0)} connections
• WebSocket Connections: {network.get('websocket_connections', 0)}
{chr(10).join([f"• IP: {conn.get('ip', 'Unknown')} - {conn.get('requests', 0)} requests (last seen: {conn.get('last_seen', 'Unknown')[:19]})" for conn in network.get('active_connections', [])[:10]]) if network.get('active_connections') else "• No active connections"}

CONNECTION MATRIX (Real-Time):
{chr(10).join([f"  {conn.get('ip', 'Unknown')}: {conn.get('requests', 0)} requests, Status: {conn.get('status', 'unknown')}" for conn in network.get('active_connections', [])]) if network.get('active_connections') else "  No connections"}

CONNECTED IP LIST: {', '.join([conn.get('ip', 'Unknown') for conn in network.get('active_connections', [])][:10]) if network.get('active_connections') else 'None'}

Recent Security Events:
{chr(10).join([f"• {t.get('threat_type', 'Unknown')} attack from IP {t.get('ip', 'Unknown')} - {t.get('action', 'blocked')}" for t in threats]) if threats else "• No recent security events"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ANSWER ALL QUESTIONS using the data above. Examples:
- "What IPs are connected?" → List the IPs from Active Network Connections
- "Show blocked IPs" → List IPs from Blocked IP Addresses section
- "Any threats?" → Summarize Attack Types Detected
- "Connection details" → Provide Active Network Connections info

Be direct and specific. Use the actual data provided above. Don't refuse to answer - you have all the information needed."""

    return context

@app.route('/chat', methods=['POST'])
def chat():
    """Handle chat messages with WAF data integration"""
    try:
        data = request.json
        message = data.get('message', '')
        history = data.get('conversation_history', [])
        
        print(f"💬 Received message: {message}")
        
        # Get real-time WAF data
        print("📡 Fetching WAF data from API...")
        waf_data = get_waf_data()
        
        if not waf_data:
            return jsonify({
                "success": False,
                "response": "⚠️ Cannot connect to WAF API. Make sure the WAF server is running on port 5000."
            })
        
        # Build context with real data
        system_msg = build_context_message(waf_data)
        
        # Debug: Show what data we're sending
        print(f"📊 WAF Data Summary:")
        print(f"  - Blocked IPs: {len(waf_data.get('blocked_ips', []))}")
        print(f"  - Active Connections: {waf_data.get('network_monitor', {}).get('total_active', 0)}")
        print(f"  - Connection list: {waf_data.get('network_monitor', {}).get('active_connections', [])}")
        print(f"  - Recent Threats: {len(waf_data.get('threats', []))}")
        print(f"\n🔍 System Context Preview:")
        print(system_msg[:800] + "...")
        
        # Prepare messages for LM Studio
        messages = [{"role": "system", "content": system_msg}]
        messages.extend(history[-5:])  # Last 5 messages for context
        messages.append({"role": "user", "content": message})
        
        print(f"🤖 Calling LM Studio...")
        
        # Call LM Studio API
        response = requests.post(
            "http://localhost:1234/v1/chat/completions",
            json={
                "messages": messages,
                "temperature": 0.7,
                "max_tokens": 600,
                "stream": False
            },
            timeout=120
        )
        
        if response.status_code == 200:
            result = response.json()
            ai_response = result["choices"][0]["message"]["content"]
            
            print(f"✅ Got response: {ai_response[:50]}...")
            
            return jsonify({
                "success": True,
                "response": ai_response,
                "stats": {
                    "blocked": waf_data.get("stats", {}).get("threats_blocked", 0),
                    "total_events": waf_data.get("stats", {}).get("total_events", 0)
                }
            })
        else:
            return jsonify({
                "success": False,
                "response": "LM Studio error. Make sure it's running on port 1234."
            })
            
    except requests.exceptions.ConnectionError as e:
        if "1234" in str(e):
            return jsonify({
                "success": False,
                "response": "⚠️ Can't connect to LM Studio. Please:\n1. Open LM Studio\n2. Load your Llama 3.2 3B model\n3. Start Local Server (port 1234)"
            })
        else:
            return jsonify({
                "success": False,
                "response": "⚠️ Can't connect to WAF API. Make sure WAF is running on port 5000."
            })
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({
            "success": False,
            "response": f"Error: {str(e)}"
        })

@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    # Check WAF API connectivity
    try:
        resp = requests.get(f"{WAF_API_URL}/stats", timeout=1)
        waf_status = "connected" if resp.status_code == 200 else "disconnected"
    except:
        waf_status = "disconnected"
    
    # Check LM Studio connectivity
    try:
        resp = requests.get("http://localhost:1234/v1/models", timeout=1)
        lm_status = "connected" if resp.status_code == 200 else "disconnected"
    except:
        lm_status = "disconnected"
    
    return jsonify({
        "status": "ok",
        "service": "VigilEdge Chatbot",
        "waf_api": waf_status,
        "lm_studio": lm_status
    })

if __name__ == '__main__':
    print("🤖 VigilEdge Chatbot Server (WAF API Integration)")
    print("=" * 60)
    print("Server: http://localhost:5001")
    print("Endpoint: POST /chat")
    print("=" * 60)
    print("📡 Connecting to:")
    print(f"  - WAF API: {WAF_API_URL}")
    print("  - LM Studio: http://localhost:1234")
    print("=" * 60)
    print("Make sure:")
    print("  1. WAF is running on port 5000")
    print("  2. LM Studio is running on port 1234 with Llama 3.2 3B")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5001, debug=False)


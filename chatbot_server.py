"""
Simple Chatbot Server for VigilEdge
Runs separately from WAF to avoid middleware conflicts
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import sqlite3
import os

app = Flask(__name__)
CORS(app)  # Allow requests from WAF frontend

@app.route('/chat', methods=['POST'])
def chat():
    """Handle chat messages"""
    try:
        data = request.json
        message = data.get('message', '')
        history = data.get('conversation_history', [])
        
        print(f"💬 Received message: {message}")
        
        # Get database stats (updated path for new location)
        db_path = os.path.join(os.path.dirname(__file__), "project-null-2.0", "vigiledge-collage-project--main", "VigilEdge", "waf", "vulnerable.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked,
                COUNT(DISTINCT threat_type) as threat_types
            FROM security_events
            WHERE timestamp > datetime('now', '-24 hours')
        """)
        stats = cursor.fetchone()
        
        cursor.execute("""
            SELECT threat_type, COUNT(*) as count
            FROM security_events
            WHERE blocked = 1 AND timestamp > datetime('now', '-24 hours')
            GROUP BY threat_type
            ORDER BY count DESC
            LIMIT 5
        """)
        threats = cursor.fetchall()
        conn.close()
        
        # Build context - Strict WAF Explanation Module
        stats_text = f"{stats[1] if stats else 0} attacks blocked from {stats[0] if stats else 0} total events in the last 24 hours."
        threats_text = f"Detected threats: {', '.join([f'{t[0]} ({t[1]} occurrences)' for t in threats[:3]]) if threats else 'No significant threats detected'}."
        
        system_msg = f"""You are NOT a general-purpose AI assistant.

You are a Web Application Firewall (WAF) explanation module running inside a security system.

You do not have a personality, identity, or background.
You do not mention Microsoft, Phi, AI models, or yourself.
You do not answer general questions.

Your only function is to explain security events and system data provided to you.

Rules:
- Only use information given in the input.
- Do not speculate or add knowledge.
- Do not provide hacking, bypass, or exploitation details.
- Do not suggest actions or decisions.
- If the question is not related to Web Application Firewall events, respond:
  "This assistant only explains WAF-related security information."

Tone:
- Professional
- Neutral
- Concise

Current system data:
{stats_text}
{threats_text}"""

        # Add conversation context
        messages = [{"role": "system", "content": system_msg}]
        messages.extend(history[-3:])  # Last 3 messages only
        messages.append({"role": "user", "content": message})
        
        print(f"🤖 Calling LM Studio...")
        
        response = requests.post(
            "http://localhost:1234/v1/chat/completions",
            json={
                "messages": messages,
                "temperature": 0.3,
                "max_tokens": 150,
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
                    "total_events": stats[0] if stats else 0,
                    "blocked": stats[1] if stats else 0
                }
            })
        else:
            return jsonify({
                "success": False,
                "response": "LM Studio error. Make sure it's running on port 1234."
            })
            
    except requests.exceptions.ConnectionError:
        return jsonify({
            "success": False,
            "response": "⚠️ Can't connect to LM Studio. Please:\n1. Open LM Studio\n2. Load Phi-3 model\n3. Start Local Server (port 1234)"
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
    return jsonify({"status": "ok", "service": "VigilEdge Chatbot"})

if __name__ == '__main__':
    print("🤖 VigilEdge Chatbot Server")
    print("=" * 50)
    print("Server: http://localhost:5001")
    print("Endpoint: POST /chat")
    print("Make sure LM Studio is running on port 1234")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5001, debug=False)

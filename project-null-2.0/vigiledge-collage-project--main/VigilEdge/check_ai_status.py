import sqlite3

conn = sqlite3.connect('waf/vulnerable.db')
cursor = conn.cursor()

# Check AI scored events
cursor.execute("SELECT COUNT(*) FROM security_events WHERE json_extract(details, '$.ai.ai_score') IS NOT NULL")
ai_count = cursor.fetchone()[0]

# Check total events
cursor.execute("SELECT COUNT(*) FROM security_events")
total_count = cursor.fetchone()[0]

# Check recent events with details
cursor.execute("""
    SELECT timestamp, threat_type, blocked, details 
    FROM security_events 
    ORDER BY timestamp DESC 
    LIMIT 5
""")
recent = cursor.fetchall()

print(f"📊 Database Status:")
print(f"   Total events: {total_count}")
print(f"   Events with AI scores: {ai_count}")
print(f"\n📋 Recent 5 Events:")
for i, (ts, threat, blocked, details) in enumerate(recent, 1):
    import json
    try:
        d = json.loads(details) if details else {}
        has_ai = 'ai' in d
        ai_score = d.get('ai', {}).get('ai_score', 'N/A') if has_ai else 'N/A'
    except:
        has_ai = False
        ai_score = 'N/A'
    
    print(f"   {i}. {ts[:19]} | {threat} | Blocked: {blocked} | AI: {ai_score}")

conn.close()

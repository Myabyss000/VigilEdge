import sqlite3
import json
from datetime import datetime

print("\n" + "="*80)
print("        VigilEdge AI Analysis Viewer")
print("="*80 + "\n")

# The database is in the waf directory and named vulnerable.db
conn = sqlite3.connect('waf/vulnerable.db')
cursor = conn.cursor()

# Check total events
cursor.execute('SELECT COUNT(*) FROM security_events')
total = cursor.fetchone()[0]
print(f'Total events in database: {total}')

# Check events with AI data
cursor.execute('''
    SELECT COUNT(*) FROM security_events 
    WHERE json_extract(details, "$.ai") IS NOT NULL
''')
ai_events = cursor.fetchone()[0]
print(f'Events with AI data: {ai_events}')

# Show recent events with AI scores
cursor.execute('''
    SELECT event_id, timestamp, threat_type, blocked, ip, url, details 
    FROM security_events 
    WHERE json_extract(details, "$.ai") IS NOT NULL
    ORDER BY timestamp DESC 
    LIMIT 10
''')
rows = cursor.fetchall()

print(f'\n{"="*80}')
print(f'Recent {len(rows)} events with AI scoring:')
print("="*80)

for row in rows:
    event_id, timestamp, threat_type, blocked, ip, url, details_json = row
    details = json.loads(details_json) if details_json else {}
    ai_data = details.get('ai', {})
    
    print(f'\n[Event: {event_id}]')
    print(f'  Timestamp: {timestamp}')
    print(f'  IP: {ip}')
    print(f'  URL: {url[:80]}...' if len(url) > 80 else f'  URL: {url}')
    print(f'  Threat Type: {threat_type}')
    print(f'  Blocked: {"YES" if blocked else "NO"}')
    
    if ai_data:
        score = ai_data.get('ai_score', 0)
        confidence = ai_data.get('ai_confidence', 0)
        note = ai_data.get('note', 'N/A')
        
        # Color code the score
        if score > 0.7:
            score_status = "HIGH RISK"
        elif score > 0.3:
            score_status = "MEDIUM RISK"
        else:
            score_status = "LOW RISK"
        
        print(f'\n  AI Analysis:')
        print(f'    Score: {score} ({score_status})')
        print(f'    Confidence: {confidence}')
        print(f'    Reason: {note}')
        
        if ai_data.get('flagged'):
            print(f'    >>> FLAGGED: {", ".join(ai_data.get("flag_reasons", []))}')
        
        if 'model' in ai_data:
            model_data = ai_data['model']
            print(f'\n  ML Model Prediction:')
            print(f'    Type: {model_data.get("model_type")}')
            print(f'    Predicted Severity: {model_data.get("suggested_severity")}')
            print(f'    Model Confidence: {model_data.get("model_confidence")}')
    
    print('-'*80)

conn.close()
print(f'\n{"="*80}')
print('[COMPLETE] Analysis finished!')
print('\nNote: This shows HEURISTIC AI scores (no ML model loaded)')
print('To train a model: python waf/scripts/train_alert_model.py')
print("="*80 + "\n")

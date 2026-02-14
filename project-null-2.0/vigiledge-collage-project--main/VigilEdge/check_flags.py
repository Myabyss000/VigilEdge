import sqlite3
import json

conn = sqlite3.connect('waf/vulnerable.db')
c = conn.cursor()

c.execute('''SELECT url, threat_type, details 
             FROM security_events 
             ORDER BY timestamp DESC LIMIT 15''')

print("Recent requests with MODEL predictions:\n")
for row in c.fetchall():
    url, threat_type, details_json = row
    details = json.loads(details_json) if details_json else {}
    ai = details.get('ai', {})
    
    score = ai.get('ai_score', 0)
    flagged = ai.get('flagged', False)
    note = ai.get('note', 'N/A')
    flag_reasons = ai.get('flag_reasons', [])
    
    # Model predictions
    model_score = ai.get('model_score', 'N/A')
    model_conf = ai.get('model_confidence', 'N/A')
    model_label = ai.get('model_label', 'N/A')
    
    print(f"URL: {url[:70]}")
    print(f"  Threat: {threat_type}")
    print(f"  AI Score: {score}")
    print(f"  Model Label: {model_label} | Model Score: {model_score} | Model Conf: {model_conf}")
    print(f"  Flagged: {'🚩 YES' if flagged else 'No'} {flag_reasons}")
    print()

conn.close()

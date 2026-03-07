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
    refined_severity = ai.get('severity_refined') or ai.get('severity', 'N/A')
    
    # Model predictions
    model = ai.get('model', {}) if isinstance(ai.get('model'), dict) else {}
    model_score = model.get('model_score', 'N/A')
    model_conf = model.get('model_confidence', 'N/A')
    model_label = model.get('predicted_label', 'N/A')
    model_severity = model.get('suggested_severity', 'N/A')
    
    print(f"URL: {url[:70]}")
    print(f"  Threat: {threat_type}")
    print(f"  AI Score: {score}")
    print(f"  Refined Severity: {refined_severity}")
    print(f"  Model Label: {model_label} | Model Severity: {model_severity} | Model Score: {model_score} | Model Conf: {model_conf}")
    print(f"  Flagged: {'🚩 YES' if flagged else 'No'} {flag_reasons}")
    print()

conn.close()

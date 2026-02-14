"""
Export security events from database to CSV for model training.
"""
import sqlite3
import csv
import json
from datetime import datetime

db_path = "waf/vulnerable.db"

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Get events with AI scores
cursor.execute("""
    SELECT 
        timestamp,
        ip,
        url,
        user_agent,
        threat_type,
        threat_level,
        action,
        blocked,
        details
    FROM security_events 
    WHERE json_extract(details, '$.ai.ai_score') IS NOT NULL
    ORDER BY timestamp DESC
""")

rows = cursor.fetchall()
conn.close()

# Write to CSV
output_file = "waf/scripts/training_data.csv"
with open(output_file, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    
    # Write header
    writer.writerow([
        'timestamp', 'source_ip', 'target_url', 'user_agent', 
        'ddos_score', 'payload_length', 'text', 'label'
    ])
    
    # Write data
    for row in rows:
        timestamp, ip, url, user_agent, threat_type, threat_level, action, blocked, details_json = row
        
        try:
            details = json.loads(details_json) if details_json else {}
        except:
            details = {}
        
        # Extract features
        ddos_score = 5 if 'ddos' in threat_type.lower() else 0
        payload_length = len(url)
        text = f"{url} {user_agent}"
        
        # Label: 0=normal, 1=suspicious, 2=attack
        if blocked:
            label = 2  # Attack
        elif threat_level in ['HIGH', 'CRITICAL']:
            label = 2  # Attack
        elif threat_level in ['MEDIUM']:
            label = 1  # Suspicious
        else:
            label = 0  # Normal
        
        writer.writerow([
            timestamp, ip, url, user_agent,
            ddos_score, payload_length, text, label
        ])

print(f"✓ Exported {len(rows)} events to {output_file}")
print(f"\nTo train the model, run:")
print(f"  python waf/scripts/train_alert_model.py --input waf/scripts/training_data.csv --output waf/models/alert_model.joblib")

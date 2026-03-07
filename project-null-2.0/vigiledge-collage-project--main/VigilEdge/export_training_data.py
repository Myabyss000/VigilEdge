"""
Export security events from database to CSV for model training.
"""
import sqlite3
import csv
import json
from typing import Any, Dict

db_path = "waf/vulnerable.db"

SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def normalize_severity_label(threat_level: Any, threat_type: Any, blocked: bool) -> str:
    level = str(threat_level or "").strip().upper()
    if level not in SEVERITY_RANK:
        if blocked and threat_type and threat_type != "none":
            level = "HIGH"
        elif threat_type and threat_type != "none":
            level = "MEDIUM"
        else:
            level = "INFO"

    if blocked:
        if threat_type == "rate_limit_exceeded":
            level = max((level, "MEDIUM"), key=lambda item: SEVERITY_RANK[item])
        elif threat_type and threat_type != "none":
            level = max((level, "HIGH"), key=lambda item: SEVERITY_RANK[item])

    return level

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
        'threat_type', 'threat_level', 'method', 'action', 'blocked',
        'ddos_score', 'payload_length', 'ai_score', 'ai_confidence', 'text', 'label'
    ])
    
    # Write data
    for row in rows:
        timestamp, ip, url, user_agent, threat_type, threat_level, action, blocked, details_json = row
        
        try:
            details: Dict[str, Any] = json.loads(details_json) if details_json else {}
        except:
            details = {}
        
        ai: Dict[str, Any] = details.get("ai", {}) if isinstance(details.get("ai", {}), dict) else {}
        method = str(details.get("method", "GET"))
        ddos_score = details.get("ddos_score", 5 if 'ddos' in str(threat_type).lower() else 0)
        payload_length = len(url)
        text = f"{url} {user_agent}"
        ai_score = ai.get("ai_score", 0)
        ai_confidence = ai.get("ai_confidence", 0)
        label = normalize_severity_label(threat_level, threat_type, bool(blocked))
        
        writer.writerow([
            timestamp, ip, url, user_agent,
            threat_type, threat_level, method, action, int(bool(blocked)),
            ddos_score, payload_length, ai_score, ai_confidence, text, label
        ])

print(f"✓ Exported {len(rows)} events to {output_file}")
print(f"\nTo train the model, run:")
print(f"  python waf/scripts/train_alert_model.py --input waf/scripts/training_data.csv --output waf/models/alert_model.joblib")

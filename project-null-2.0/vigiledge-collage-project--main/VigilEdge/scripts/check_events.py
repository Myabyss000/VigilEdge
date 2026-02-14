import sqlite3
from datetime import datetime

conn = sqlite3.connect('vulnerable.db')
cursor = conn.cursor()

cursor.execute('SELECT event_id, timestamp, threat_type FROM security_events ORDER BY timestamp DESC LIMIT 10')
rows = cursor.fetchall()

print('\n📊 CURRENT EVENTS IN DATABASE:\n')
for r in rows:
    try:
        dt = datetime.fromisoformat(r[1])
        now = datetime.now()
        diff = now - dt
        mins = int(diff.total_seconds() / 60)
        hours = int(diff.total_seconds() / 3600)
        
        if hours > 0:
            print(f'  {r[2]}: {hours} hours ago ({r[1]})')
        else:
            print(f'  {r[2]}: {mins} minutes ago ({r[1]})')
    except:
        print(f'  {r[2]}: {r[1]}')

conn.close()

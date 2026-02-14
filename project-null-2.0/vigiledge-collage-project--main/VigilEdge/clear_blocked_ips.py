import sqlite3
import os

# Connect to database
db_path = 'waf/vulnerable.db'
if not os.path.exists(db_path):
    print(f"❌ Database not found at {db_path}")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Check if blocked_ips table exists
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='blocked_ips'")
table_exists = cursor.fetchone()

if not table_exists:
    print("ℹ️ No blocked_ips table found - IPs are stored in memory only")
    print("\n💡 To clear in-memory blocked IPs, restart the WAF server")
else:
    # Count blocked IPs
    cursor.execute("SELECT COUNT(*) FROM blocked_ips")
    count = cursor.fetchone()[0]
    
    print(f"Found {count} blocked IPs in database")
    
    if count > 0:
        # Clear all blocked IPs
        cursor.execute("DELETE FROM blocked_ips")
        conn.commit()
        print(f"✅ Cleared {count} blocked IPs from database")
    else:
        print("✅ No blocked IPs in database")

conn.close()
print("\n🔄 Restart the WAF server to clear in-memory blocked IPs: python waf/main.py")

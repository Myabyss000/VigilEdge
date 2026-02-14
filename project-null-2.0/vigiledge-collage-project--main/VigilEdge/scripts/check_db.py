import sqlite3

conn = sqlite3.connect('vulnerable.db')
cursor = conn.cursor()

# Get all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()

print('\n📋 TABLES IN DATABASE:')
for t in tables:
    print(f'  - {t[0]}')
    
    # Get row count for each table
    cursor.execute(f"SELECT COUNT(*) FROM {t[0]}")
    count = cursor.fetchone()[0]
    print(f'    Rows: {count}')

conn.close()

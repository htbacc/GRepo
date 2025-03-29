import sqlite3

def create_connection(db_file):
    conn = sqlite3.connect(db_file)
    return conn

def create_table(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            cve_id TEXT PRIMARY KEY,
            published_date TEXT,
            cvss_v3_score TEXT,
            cvss_v2_score TEXT,
            query_item TEXT,
            scan_date DATE
        )
    ''')
    conn.commit()

def add_missing_columns(conn):
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(vulnerabilities)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'query_item' not in columns:
        cursor.execute('''
            ALTER TABLE vulnerabilities
            ADD COLUMN query_item TEXT
        ''')
    if 'scan_date' not in columns:
        cursor.execute('''
            ALTER TABLE vulnerabilities
            ADD COLUMN scan_date DATE
        ''')
    conn.commit()

def insert_data(conn, cve_id, published_date, cvss_v3_score, cvss_v2_score, query_item):
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR IGNORE INTO vulnerabilities (cve_id, published_date, cvss_v3_score, cvss_v2_score, query_item, scan_date)
        VALUES (?, ?, ?, ?, ?, DATE('now'))
    ''', (cve_id, published_date, cvss_v3_score, cvss_v2_score, query_item))
    conn.commit()


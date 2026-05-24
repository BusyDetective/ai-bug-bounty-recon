import sqlite3

DB_NAME = "recon.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT,
        scan_date TEXT,
        findings_count INTEGER,
        high_count INTEGER,
        medium_count INTEGER,
        low_count INTEGER,
        status TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    """)

    conn.commit()
    conn.close()

def save_scan(domain, risk, findings):
    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO scans (
        domain,
        scan_date,
        findings_count,
        high_count,
        medium_count,
        low_count,
        status
    )
    VALUES (?, datetime('now'), ?, ?, ?, ?, ?)
    """, (
        domain,
        len(findings),
        len(risk["high"]),
        len(risk["medium"]),
        len(risk["low"]),
        "Completed"
    ))

    conn.commit()
    conn.close()

def get_scans():
    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    SELECT * FROM scans
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows

def create_user(username, password):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    try:
        cursor.execute("""
        INSERT INTO users (username, password)
        VALUES (?, ?)
        """, (username, password))

        conn.commit()
        return True

    except:
        return False

    finally:
        conn.close()

def authenticate_user(username):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT * FROM users
    WHERE username=?
    """, (username,))

    user = cursor.fetchone()

    conn.close()

    return user
import sqlite3
import hashlib
import os
import uuid
import logging
import shutil

DEFAULT_SAVE_PATH = os.environ.get("NEURATRACE_DATA_DIR", r"E:\Backup\Desktop\NT\saved_scans")
DB_PATH = os.path.join(DEFAULT_SAVE_PATH, "neuratrace_mgmt.db")
LEGACY_DB_PATH = os.path.join(os.path.dirname(__file__), "neuratrace_mgmt.db")

def migrate_legacy_db():
    """Preserve the legacy project-root database when moving to DATA_DIR."""
    if os.path.abspath(LEGACY_DB_PATH) == os.path.abspath(DB_PATH):
        return
    if os.path.exists(DB_PATH) or not os.path.exists(LEGACY_DB_PATH):
        return

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    shutil.copy2(LEGACY_DB_PATH, DB_PATH)
    logging.info("Migrated legacy management database to DATA_DIR.")

def init_db():
    os.makedirs(os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else ".", exist_ok=True)
    migrate_legacy_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Global Scan History Metadata table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS global_history (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            node_id TEXT,
            scan_type TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            target TEXT,
            status TEXT,
            local_path TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create default admin if not exists
    cursor.execute("SELECT * FROM users WHERE username = ?", (os.environ.get("AUTH_USER", "admin"),))
    if not cursor.fetchone():
        salt = uuid.uuid4().hex
        pwd = os.environ.get("AUTH_PASS", "admin123")
        phash = hashlib.sha256((pwd + salt).encode()).hexdigest()
        cursor.execute("INSERT INTO users (id, username, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)",
                      (uuid.uuid4().hex, os.environ.get("AUTH_USER", "admin"), phash, salt, "admin"))
    
    conn.commit()
    conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash, salt, role FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        user_id, phash, salt, role = row
        if hashlib.sha256((password + salt).encode()).hexdigest() == phash:
            return {"id": user_id, "username": username, "role": role}
    return None

def change_password(user_id, new_password):
    salt = uuid.uuid4().hex
    phash = hashlib.sha256((new_password + salt).encode()).hexdigest()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?", (phash, salt, user_id))
    conn.commit()
    conn.close()
    return True

def create_user(username, password, role="analyst"):
    salt = uuid.uuid4().hex
    phash = hashlib.sha256((password + salt).encode()).hexdigest()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (id, username, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)",
                      (uuid.uuid4().hex, username, phash, salt, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, created_at FROM users")
    users = cursor.fetchall()
    conn.close()
    return users

def add_to_global_history(user_id, node_id, scan_type, target, status, local_path):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO global_history (id, user_id, node_id, scan_type, target, status, local_path)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (uuid.uuid4().hex, user_id, node_id, scan_type, target, status, local_path))
    conn.commit()
    conn.close()

def get_global_history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT h.timestamp, u.username, h.node_id, h.scan_type, h.target, h.status, h.local_path
        FROM global_history h
        JOIN users u ON h.user_id = u.id
        ORDER BY h.timestamp DESC
    ''')
    history = cursor.fetchall()
    conn.close()
    return history

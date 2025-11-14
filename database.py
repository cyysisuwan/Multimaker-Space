import sqlite3
import os

def init_db():
    conn = sqlite3.connect('multimaker.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT DEFAULT 'student',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Class schedule table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS class_schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_name TEXT NOT NULL,
            day TEXT NOT NULL,
            time TEXT NOT NULL,
            instructor TEXT NOT NULL,
            duration TEXT NOT NULL
        )
    ''')
    
    # Student achievements table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS student_achievements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            achievement TEXT NOT NULL,
            date_achieved DATE NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Media gallery table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS media_gallery (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT NOT NULL,
            uploaded_by INTEGER NOT NULL,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (uploaded_by) REFERENCES users (id)
        )
    ''')
    
    # Insert default admin user if not exists
    from werkzeug.security import generate_password_hash
    try:
        cursor.execute(
            'INSERT INTO users (username, email, password, full_name, role) VALUES (?, ?, ?, ?, ?)',
            ('admin', 'admin@multimaker.com', generate_password_hash('admin123'), 'Administrator', 'admin')
        )
    except sqlite3.IntegrityError:
        pass  # Admin user already exists
    
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('multimaker.db')
    conn.row_factory = sqlite3.Row
    return conn
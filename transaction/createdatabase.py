import sqlite3

def create_connection():
    conn = sqlite3.connect('faces.db')
    return conn

def create_table(conn):
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       name TEXT NOT NULL,
                       age INTEGER NOT NULL,
                       gender TEXT NOT NULL,
                       image_path TEXT NOT NULL)''')
    conn.commit()

conn = create_connection()
create_table(conn)
conn.close()

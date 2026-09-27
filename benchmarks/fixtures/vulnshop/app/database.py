import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnshop.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)

    # Orders Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            item_name TEXT,
            amount REAL,
            shipping_address TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Documents Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            is_private INTEGER DEFAULT 1,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Products Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            description TEXT,
            price REAL
        )
    """)

    # Seed initial data if empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Seed Users
        cursor.execute("INSERT INTO users (username, password, role) VALUES ('alice', 'password123', 'user')") # id 1
        cursor.execute("INSERT INTO users (username, password, role) VALUES ('bob', 'password456', 'user')")   # id 2
        cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'adminpass', 'admin')")  # id 3

        # Seed Orders (Alice owns order 1, Bob owns order 2)
        cursor.execute("INSERT INTO orders (user_id, item_name, amount, shipping_address) VALUES (1, 'Quantum Cyber-Glasses', 299.99, '123 Alice St')")
        cursor.execute("INSERT INTO orders (user_id, item_name, amount, shipping_address) VALUES (2, 'Vibe-Guard Secret Keycard', 1499.00, '456 Bob Ave')")

        # Seed Documents (Alice owns doc 1, Bob owns doc 2)
        cursor.execute("INSERT INTO documents (user_id, title, content) VALUES (1, 'Alice Confidential Notes', 'Alice secret recipe for vibe-coding.')")
        cursor.execute("INSERT INTO documents (user_id, title, content) VALUES (2, 'Bob Private Financials', 'Bob bank account PIN: 9988.')")

        # Seed Products
        cursor.execute("INSERT INTO products (name, description, price) VALUES ('Quantum Cyber-Glasses', 'AR glasses', 299.99)")
        cursor.execute("INSERT INTO products (name, description, price) VALUES ('Vibe-Guard Keycard', 'Security pass', 1499.00)")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized.")

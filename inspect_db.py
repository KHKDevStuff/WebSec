import sqlite3
import os

db_path = 'instance/users.db'

if not os.path.exists(db_path):
    print(f"Database file '{db_path}' not found.")
else:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print("--- USERS ---")
    try:
        cursor.execute("SELECT id, username, role FROM user")
        users = cursor.fetchall()
        for u in users:
            print(f"ID: {u[0]}, Username: {u[1]}, Role: {u[2]}")
    except Exception as e:
        print(f"Error reading users: {e}")

    print("\n--- SCAN RESULTS ---")
    try:
        cursor.execute("SELECT id, user_id, target, risk_score, timestamp FROM scan_result")
        scans = cursor.fetchall()
        for s in scans:
            print(f"ID: {s[0]}, UserID: {s[1]}, Target: {s[2]}, Score: {s[3]}, Time: {s[4]}")
    except Exception as e:
        print(f"Error reading scans: {e}")

    conn.close()

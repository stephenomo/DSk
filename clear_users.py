import sqlite3

DB_FILE = "users.db"

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

# Delete all users
cursor.execute("DELETE FROM users")

conn.commit()
conn.close()

print("All users deleted successfully.")

import sqlite3

conn = sqlite3.connect('features.db')
cursor = conn.cursor()
cursor.execute('SELECT id, name, description, steps, passes, in_progress FROM features WHERE id = 152')
row = cursor.fetchone()

print(f"ID: {row[0]}")
print(f"Name: {row[1]}")
print(f"Description: {row[2]}")
print(f"Steps: {row[3]}")
print(f"Passes: {row[4]}")
print(f"In Progress: {row[5]}")

conn.close()

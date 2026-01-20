#!/usr/bin/env python3
import sqlite3
import json

conn = sqlite3.connect('/Users/peterryszkiewicz/Repos/sus-repo-finder/features.db')
cur = conn.cursor()
cur.execute('SELECT id, name, description, steps, passes, in_progress FROM features WHERE id = 12')
row = cur.fetchone()
if row:
    print(f"ID: {row[0]}")
    print(f"Name: {row[1]}")
    print(f"Description: {row[2]}")
    print(f"Steps: {row[3]}")
    print(f"Passes: {row[4]}")
    print(f"In Progress: {row[5]}")
else:
    print("Feature 12 not found")
conn.close()

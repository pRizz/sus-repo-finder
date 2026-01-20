#!/usr/bin/env python3
import sqlite3
import json

conn = sqlite3.connect('/Users/peterryszkiewicz/Repos/sus-repo-finder/features.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()
cursor.execute('SELECT id, name, description, steps, passes, in_progress FROM features WHERE id = 30')
row = cursor.fetchone()
if row:
    print(json.dumps(dict(row), indent=2))
conn.close()

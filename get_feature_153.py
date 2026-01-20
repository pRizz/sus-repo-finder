import sqlite3

conn = sqlite3.connect('/Users/peterryszkiewicz/Repos/sus-repo-finder/features.db')
c = conn.cursor()
c.execute('SELECT id, name, description, steps FROM features WHERE id = 153')
row = c.fetchone()
if row:
    print(f'ID: {row[0]}')
    print(f'Name: {row[1]}')
    print(f'Description: {row[2]}')
    print(f'Steps: {row[3]}')
else:
    print('Feature not found')
conn.close()

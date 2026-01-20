const Database = require('better-sqlite3');
const fs = require('fs');

// Try different database locations
const dbPaths = [
    './data/sus-repo-finder.db',
    './features.db',
    './sus-repo-finder.db'
];

for (const dbPath of dbPaths) {
    if (fs.existsSync(dbPath)) {
        console.log(`\n=== ${dbPath} ===`);
        try {
            const db = new Database(dbPath);
            const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
            console.log('Tables:', tables.map(t => t.name));
            db.close();
        } catch (e) {
            console.log('Error:', e.message);
        }
    } else {
        console.log(`${dbPath} - does not exist`);
    }
}

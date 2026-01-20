const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

// List all tables
const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
console.log('Tables:', tables.map(t => t.name));

db.close();

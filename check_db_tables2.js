const Database = require('better-sqlite3');
const db = new Database('./data/sus.db');

// List all tables
console.log("=== All tables in database ===");
const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all();
tables.forEach(t => console.log(`  ${t.name}`));

db.close();

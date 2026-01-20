const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

// Check analysis_results table structure
const columns = db.prepare("PRAGMA table_info(analysis_results)").all();
console.log('Columns:', columns.map(c => c.name));

// Check sample data
const rows = db.prepare('SELECT * FROM analysis_results LIMIT 3').all();
console.log('\nSample rows:');
rows.forEach(r => console.log(JSON.stringify(r, null, 2)));

db.close();

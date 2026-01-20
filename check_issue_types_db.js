const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');
const rows = db.prepare('SELECT issue_type, COUNT(*) as count FROM findings GROUP BY issue_type').all();
console.log(JSON.stringify(rows, null, 2));
db.close();

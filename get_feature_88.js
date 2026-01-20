const Database = require('better-sqlite3');
const db = new Database('./features.db');
const row = db.prepare('SELECT * FROM features WHERE id = 88').get();
console.log(JSON.stringify(row, null, 2));
db.close();

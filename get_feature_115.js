const Database = require('better-sqlite3');
const db = new Database('features.db');
const f = db.prepare('SELECT * FROM features WHERE id = 115').get();
console.log(JSON.stringify(f, null, 2));

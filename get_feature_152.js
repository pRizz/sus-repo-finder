const Database = require('better-sqlite3');
const db = new Database('features.db');
const row = db.prepare('SELECT id, name, description, steps, passes, in_progress FROM features WHERE id = 152').get();
console.log(JSON.stringify(row, null, 2));
db.close();

const db = require('better-sqlite3')('features.db');
const row = db.prepare('SELECT id, name, description, steps, category FROM features WHERE id = 129').get();
console.log(JSON.stringify(row, null, 2));

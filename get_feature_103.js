const db = require('better-sqlite3')('features.db');
const row = db.prepare('SELECT * FROM features WHERE id = 103').get();
console.log(JSON.stringify(row, null, 2));

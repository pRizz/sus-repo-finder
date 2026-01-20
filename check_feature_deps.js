const Database = require('better-sqlite3');
const db = new Database('features.db');
const features = db.prepare('SELECT id, name, passes FROM features WHERE id IN (5, 29, 42)').all();
console.log(JSON.stringify(features, null, 2));

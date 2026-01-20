const Database = require('better-sqlite3');
const db = new Database('features.db');
const row = db.prepare('SELECT id, name, description, steps FROM features WHERE id = 23').get();
console.log('ID:', row.id);
console.log('Name:', row.name);
console.log('Description:', row.description);
console.log('Steps:', row.steps);
db.close();

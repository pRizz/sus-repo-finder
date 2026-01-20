const Database = require('better-sqlite3');
const db = new Database('features.db');
const row = db.prepare('SELECT id, category, name, description, steps FROM features WHERE id = 46').get();
if (row) {
  console.log('ID:', row.id);
  console.log('Category:', row.category);
  console.log('Name:', row.name);
  console.log('Description:', row.description);
  console.log('Steps:', row.steps);
}
db.close();

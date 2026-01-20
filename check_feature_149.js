const Database = require('better-sqlite3');
const db = new Database('./features.db', { readonly: true });
const row = db.prepare('SELECT * FROM features WHERE id = 149').get();
if (row) {
    console.log('ID:', row.id);
    console.log('Priority:', row.priority);
    console.log('Category:', row.category);
    console.log('Name:', row.name);
    console.log('Description:', row.description);
    console.log('Steps:', row.steps);
    console.log('Passes:', row.passes);
    console.log('In Progress:', row.in_progress);
}
db.close();

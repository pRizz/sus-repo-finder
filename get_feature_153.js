const Database = require('better-sqlite3');
const db = new Database('/Users/peterryszkiewicz/Repos/sus-repo-finder/features.db');
const row = db.prepare('SELECT id, name, description, steps FROM features WHERE id = 153').get();
if (row) {
    console.log('ID:', row.id);
    console.log('Name:', row.name);
    console.log('Description:', row.description);
    console.log('Steps:', row.steps);
} else {
    console.log('Feature not found');
}
db.close();

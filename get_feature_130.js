const Database = require('better-sqlite3');
const db = new Database('/Users/peterryszkiewicz/Repos/sus-repo-finder/features.db');
const row = db.prepare('SELECT id, category, name, description, steps FROM features WHERE id = 130').get();
console.log(JSON.stringify(row, null, 2));

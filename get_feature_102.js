const Database = require('better-sqlite3');
const db = new Database('/Users/peterryszkiewicz/Repos/sus-repo-finder/features.db');
const row = db.prepare('SELECT id, name, description, steps FROM features WHERE id = 102').get();
console.log(JSON.stringify(row, null, 2));

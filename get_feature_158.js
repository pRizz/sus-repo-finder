const db = require('better-sqlite3')('/Users/peterryszkiewicz/Repos/sus-repo-finder/features.db');
const f = db.prepare('SELECT * FROM features WHERE id = 158').get();
console.log(JSON.stringify(f, null, 2));

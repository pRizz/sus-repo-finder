const Database = require('better-sqlite3');
const db = new Database('/Users/peterryszkiewicz/Repos/sus-repo-finder/data/sus-repo-finder.db');
const count = db.prepare('SELECT COUNT(*) as count FROM crates').get();
console.log('Crate count:', count.count);
db.close();

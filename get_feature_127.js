const Database = require('better-sqlite3');
const db = new Database('/Users/peterryszkiewicz/Repos/sus-repo-finder/features.db');
const feature = db.prepare('SELECT * FROM features WHERE id = 127').get();
console.log(JSON.stringify(feature, null, 2));
db.close();

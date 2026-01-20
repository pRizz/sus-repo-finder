const sqlite3 = require('better-sqlite3');
const db = new sqlite3('/Users/peterryszkiewicz/Repos/sus-repo-finder/features.db');
const feature = db.prepare('SELECT id, category, name, description, steps, passes, in_progress FROM features WHERE id = 117').get();
console.log(JSON.stringify(feature, null, 2));
db.close();

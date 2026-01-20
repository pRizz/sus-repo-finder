const Database = require('better-sqlite3');
const db = new Database('data/sus-repo-finder.db', { readonly: true });

console.log('=== crawler_errors table schema ===');
try {
  const schema = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='crawler_errors'").get();
  console.log(schema ? schema.sql : 'Table does not exist');
} catch(e) {
  console.log('Error:', e.message);
}

console.log('');
console.log('=== Recent crawler errors ===');
try {
  const errors = db.prepare('SELECT * FROM crawler_errors ORDER BY occurred_at DESC LIMIT 5').all();
  console.log(JSON.stringify(errors, null, 2));
} catch(e) {
  console.log('Error:', e.message);
}

db.close();

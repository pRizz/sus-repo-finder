const Database = require('better-sqlite3');
const db = new Database('data/sus-repo-finder.db', { readonly: true });

console.log('=== Crawler error count ===');
const count = db.prepare('SELECT COUNT(*) as count FROM crawler_errors').get();
console.log('Count:', count.count);

console.log('');
console.log('=== All errors ===');
const errors = db.prepare('SELECT id, crate_name, error_type, occurred_at FROM crawler_errors ORDER BY id').all();
errors.forEach(e => {
  console.log(`  ${e.id}: ${e.crate_name} - ${e.error_type} @ ${e.occurred_at}`);
});

db.close();

const Database = require('better-sqlite3');
const db = new Database('features.db');
const deps = [4, 54];
deps.forEach(id => {
  const row = db.prepare('SELECT id, name, passes FROM features WHERE id = ?').get(id);
  console.log(`Feature #${id}: ${row.name} - passes: ${row.passes}`);
});

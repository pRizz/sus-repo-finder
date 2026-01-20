const Database = require('better-sqlite3');
const db = new Database('./data/sus.db');

// List all tables
console.log("=== All tables in database ===");
const tables = db.prepare(`
  SELECT name, type FROM sqlite_master
  WHERE type IN ('table', 'view')
  ORDER BY name
`).all();
console.log(JSON.stringify(tables, null, 2));

// Also show count
console.log(`\nTotal: ${tables.length} tables/views`);

db.close();

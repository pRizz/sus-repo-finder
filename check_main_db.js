const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

// List all tables
console.log("=== All tables in sus-repo-finder.db ===");
const tables = db.prepare(`
  SELECT name, type FROM sqlite_master
  WHERE type IN ('table', 'view')
  ORDER BY name
`).all();
tables.forEach(t => console.log(`  ${t.name} (${t.type})`));

// Check if crawler_state exists
console.log("\n=== crawler_state table ===");
const hasTable = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='crawler_state'").get();
if (hasTable) {
  const schema = db.prepare("PRAGMA table_info(crawler_state)").all();
  schema.forEach(col => console.log(`  ${col.name} (${col.type})`));

  const rows = db.prepare("SELECT * FROM crawler_state LIMIT 5").all();
  console.log("\nRows:");
  console.log(JSON.stringify(rows, null, 2));
} else {
  console.log("  Table does not exist");
}

// Check crawler_queue
console.log("\n=== crawler_queue table ===");
const hasQueue = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='crawler_queue'").get();
if (hasQueue) {
  const stats = db.prepare(`SELECT status, COUNT(*) as count FROM crawler_queue GROUP BY status`).all();
  console.log(JSON.stringify(stats, null, 2));
} else {
  console.log("  Table does not exist");
}

db.close();

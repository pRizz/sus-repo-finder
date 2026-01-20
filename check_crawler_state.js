const Database = require('better-sqlite3');
const db = new Database('./data/sus.db');

// Check table schema
console.log("=== crawler_state table schema ===");
const schema = db.prepare("PRAGMA table_info(crawler_state)").all();
schema.forEach(col => console.log(`  ${col.name} (${col.type})`));

// Check current state
console.log("\n=== Current crawler_state rows ===");
const states = db.prepare("SELECT * FROM crawler_state ORDER BY id DESC LIMIT 5").all();
console.log(JSON.stringify(states, null, 2));

// Check queue status
console.log("\n=== Crawler queue summary ===");
const queueStats = db.prepare(`
  SELECT status, COUNT(*) as count
  FROM crawler_queue
  GROUP BY status
`).all();
console.log(JSON.stringify(queueStats, null, 2));

db.close();

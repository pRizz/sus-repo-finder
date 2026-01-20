const Database = require("better-sqlite3");
const db = new Database("/Users/peterryszkiewicz/Repos/sus-repo-finder/data/sus-repo-finder.db");

// Verify "anyhow" is NOT in the "test" search results
const anyhowInTest = db.prepare("SELECT name FROM crates WHERE name LIKE '%test%' AND name = 'anyhow'").all();
console.log("anyhow in 'test' search results:", anyhowInTest.length > 0 ? "YES (BUG!)" : "NO (correct)");

// Verify some non-test crates are excluded from test search
const excluded = ["actix-web", "anyhow", "axum", "bytes", "clap", "chrono"];
console.log("\nVerifying excluded crates:");
excluded.forEach(name => {
  const found = db.prepare("SELECT name FROM crates WHERE name LIKE '%test%' AND name = ?").get(name);
  console.log(`  ${name}: ${found ? "FOUND (BUG!)" : "EXCLUDED (correct)"}`);
});

// Count test crates (should be 403)
const testCount = db.prepare("SELECT COUNT(*) as count FROM crates WHERE name LIKE '%test%'").get();
console.log("\nTotal crates matching 'test':", testCount.count);

db.close();

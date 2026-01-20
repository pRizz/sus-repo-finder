const Database = require("better-sqlite3");
const db = new Database("/Users/peterryszkiewicz/Repos/sus-repo-finder/data/sus-repo-finder.db");

// Check for crates matching test-foo, test-bar pattern
const testCrates = db.prepare("SELECT name FROM crates WHERE name LIKE 'test-%' OR name LIKE '%-test' LIMIT 20").all();
console.log("Test crates found:", testCrates.length);
testCrates.forEach(c => console.log("  -", c.name));

// Get some sample crate names
const sampleCrates = db.prepare("SELECT name FROM crates LIMIT 10").all();
console.log("\nSample crates:");
sampleCrates.forEach(c => console.log("  -", c.name));

// Count total crates
const total = db.prepare("SELECT COUNT(*) as count FROM crates").get();
console.log("\nTotal crates:", total.count);

db.close();

const Database = require("better-sqlite3");
const db = new Database("/Users/peterryszkiewicz/Repos/sus-repo-finder/data/sus-repo-finder.db");

// Find crates that do NOT contain 'test' in their name
const nonTestCrates = db.prepare("SELECT name FROM crates WHERE name NOT LIKE '%test%' LIMIT 20").all();
console.log("Non-test crates found:", nonTestCrates.length);
nonTestCrates.forEach(c => console.log("  -", c.name));

// Count non-test crates
const countNonTest = db.prepare("SELECT COUNT(*) as count FROM crates WHERE name NOT LIKE '%test%'").get();
console.log("\nTotal non-test crates:", countNonTest.count);

db.close();

const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

// Step 1: Check if we have any test crates
console.log("=== Step 1: Check existing crates ===");
const crates = db.prepare("SELECT * FROM crates LIMIT 5").all();
console.log(`Total crates in DB: ${db.prepare("SELECT COUNT(*) as count FROM crates").get().count}`);
console.log("Sample crates:", crates.map(c => c.name));

// Get a specific crate to test with
const testCrate = db.prepare("SELECT * FROM crates WHERE name = 'test-crate-0001'").get();
if (testCrate) {
    console.log("\n=== Test crate found ===");
    console.log("Name:", testCrate.name);
    console.log("ID:", testCrate.id);
    console.log("Description:", testCrate.description);
    console.log("Download count:", testCrate.download_count);

    // Check versions for this crate
    const versions = db.prepare("SELECT * FROM versions WHERE crate_id = ?").all(testCrate.id);
    console.log("Versions:", versions.map(v => v.version_number));
} else {
    console.log("\ntest-crate-0001 not found");

    // Try another crate
    const anyhowCrate = db.prepare("SELECT * FROM crates WHERE name = 'anyhow'").get();
    if (anyhowCrate) {
        console.log("\n=== anyhow crate found ===");
        console.log("Name:", anyhowCrate.name);
        console.log("ID:", anyhowCrate.id);
        console.log("Description:", anyhowCrate.description);
        console.log("Download count:", anyhowCrate.download_count);

        const versions = db.prepare("SELECT * FROM versions WHERE crate_id = ?").all(anyhowCrate.id);
        console.log("Versions:", versions.map(v => v.version_number));
    }
}

db.close();

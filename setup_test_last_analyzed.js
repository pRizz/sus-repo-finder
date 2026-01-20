const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

// Set last_analyzed timestamps for some versions to test sorting
// We'll use different timestamps to verify sorting works correctly

const updates = [
    // Most recent - serde (should appear first when sorted by recent)
    { crate_name: 'serde', offset_minutes: 0 },
    // Second most recent - tokio
    { crate_name: 'tokio', offset_minutes: 10 },
    // Third - anyhow
    { crate_name: 'anyhow', offset_minutes: 20 },
    // Fourth - rand
    { crate_name: 'rand', offset_minutes: 30 },
    // Fifth - regex
    { crate_name: 'regex', offset_minutes: 40 },
    // Sixth - log
    { crate_name: 'log', offset_minutes: 50 },
    // Seventh - chrono
    { crate_name: 'chrono', offset_minutes: 60 },
    // Eighth - syn
    { crate_name: 'syn', offset_minutes: 70 },
    // Ninth - quote
    { crate_name: 'quote', offset_minutes: 80 },
    // Tenth - proc-macro2
    { crate_name: 'proc-macro2', offset_minutes: 90 },
];

// Update versions with last_analyzed timestamps
const updateStmt = db.prepare(`
    UPDATE versions
    SET last_analyzed = datetime('now', '-' || ? || ' minutes')
    WHERE crate_id = (SELECT id FROM crates WHERE name = ?)
`);

for (const update of updates) {
    const result = updateStmt.run(update.offset_minutes, update.crate_name);
    console.log(`Updated ${update.crate_name}: ${result.changes} row(s) affected (offset: ${update.offset_minutes} minutes ago)`);
}

// Verify the updates
const check = db.prepare(`
    SELECT c.name as crate_name, v.version_number, v.last_analyzed
    FROM versions v
    JOIN crates c ON v.crate_id = c.id
    WHERE v.last_analyzed IS NOT NULL
    ORDER BY v.last_analyzed DESC
`).all();

console.log("\nVersions with last_analyzed (sorted by DESC):");
for (const row of check) {
    console.log(`  ${row.crate_name} v${row.version_number}: ${row.last_analyzed}`);
}

db.close();
console.log("\nDone setting up test data for last_analyzed timestamps.");

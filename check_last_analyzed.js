const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

// Get versions with their crate names, showing last_analyzed timestamps
const versions = db.prepare(`
    SELECT c.name as crate_name, v.version_number, v.last_analyzed
    FROM versions v
    JOIN crates c ON v.crate_id = c.id
    ORDER BY v.last_analyzed DESC NULLS LAST
    LIMIT 20
`).all();

console.log("Versions by last_analyzed (DESC):");
console.log(JSON.stringify(versions, null, 2));

// Count versions with non-null last_analyzed
const countWithTimestamp = db.prepare(`
    SELECT COUNT(*) as count FROM versions WHERE last_analyzed IS NOT NULL
`).get();
console.log("\nVersions with last_analyzed timestamp:", countWithTimestamp.count);

const totalVersions = db.prepare('SELECT COUNT(*) as count FROM versions').get();
console.log("Total versions:", totalVersions.count);

db.close();

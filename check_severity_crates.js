const Database = require('better-sqlite3');
const db = new Database('/Users/peterryszkiewicz/Repos/sus-repo-finder/data/sus-repo-finder.db');

// Check how many crates have each severity level
const highCount = db.prepare(`
    SELECT COUNT(DISTINCT c.id) as count
    FROM crates c
    JOIN versions v ON v.crate_id = c.id
    JOIN analysis_results ar ON ar.version_id = v.id
    GROUP BY c.id
    HAVING MAX(ar.severity) = 'high'
`).all().length;

const mediumCount = db.prepare(`
    SELECT COUNT(DISTINCT c.id) as count
    FROM crates c
    JOIN versions v ON v.crate_id = c.id
    JOIN analysis_results ar ON ar.version_id = v.id
    GROUP BY c.id
    HAVING MAX(ar.severity) = 'medium'
`).all().length;

const lowCount = db.prepare(`
    SELECT COUNT(DISTINCT c.id) as count
    FROM crates c
    JOIN versions v ON v.crate_id = c.id
    JOIN analysis_results ar ON ar.version_id = v.id
    GROUP BY c.id
    HAVING MAX(ar.severity) = 'low'
`).all().length;

// Crates with no findings
const noFindingsCount = db.prepare(`
    SELECT COUNT(*) as count
    FROM crates c
    WHERE NOT EXISTS (
        SELECT 1 FROM analysis_results ar
        JOIN versions v ON ar.version_id = v.id
        WHERE v.crate_id = c.id
    )
`).get().count;

console.log('Severity Distribution:');
console.log(`  High:    ${highCount} crates`);
console.log(`  Medium:  ${mediumCount} crates`);
console.log(`  Low:     ${lowCount} crates`);
console.log(`  No Findings: ${noFindingsCount} crates`);

// Get some example high severity crates
const highCrates = db.prepare(`
    SELECT c.name, MAX(ar.severity) as max_sev
    FROM crates c
    JOIN versions v ON v.crate_id = c.id
    JOIN analysis_results ar ON ar.version_id = v.id
    GROUP BY c.id
    HAVING MAX(ar.severity) = 'high'
    LIMIT 5
`).all();
console.log('\nExample high severity crates:');
highCrates.forEach(c => console.log(`  - ${c.name}`));

db.close();

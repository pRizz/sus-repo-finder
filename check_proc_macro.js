const Database = require('better-sqlite3');
const db = new Database('/Users/peterryszkiewicz/Repos/sus-repo-finder/data/sus-repo-finder.db');

// Check for proc-macro crates in the database
console.log("Checking for proc-macro crates in database...\n");

// Get all versions with is_proc_macro flag
const procMacroVersions = db.prepare(`
    SELECT c.name, v.version_number, v.is_proc_macro, v.has_build_rs, v.last_analyzed
    FROM versions v
    JOIN crates c ON v.crate_id = c.id
    WHERE v.is_proc_macro = 1
    ORDER BY c.name
`).all();

console.log(`Found ${procMacroVersions.length} proc-macro crates:\n`);
procMacroVersions.forEach(v => {
    console.log(`  - ${v.name}@${v.version_number} (has_build_rs: ${v.has_build_rs})`);
});

// Get total version count for comparison
const totalVersions = db.prepare(`SELECT COUNT(*) as count FROM versions`).get();
console.log(`\nTotal versions in database: ${totalVersions.count}`);
console.log(`Proc-macro crates: ${procMacroVersions.length} (${(procMacroVersions.length / totalVersions.count * 100).toFixed(1)}%)`);

// Check for any analysis results from proc-macro crates
const procMacroFindings = db.prepare(`
    SELECT c.name, v.version_number, ar.issue_type, ar.severity, ar.file_path
    FROM analysis_results ar
    JOIN versions v ON ar.version_id = v.id
    JOIN crates c ON v.crate_id = c.id
    WHERE v.is_proc_macro = 1
    LIMIT 10
`).all();

console.log(`\nFindings from proc-macro crates: ${procMacroFindings.length}`);
if (procMacroFindings.length > 0) {
    console.log("Examples:");
    procMacroFindings.forEach(f => {
        console.log(`  - ${f.name}: ${f.issue_type} (${f.severity}) in ${f.file_path}`);
    });
}

db.close();

const Database = require('better-sqlite3');
const db = new Database('data/sus-repo-finder.db');

// Check what tables exist
const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
console.log('Tables in database:');
console.log(tables.map(t => t.name));

// Check what issue types exist in the database
try {
    const rows = db.prepare('SELECT issue_type, COUNT(*) as count FROM analysis_results GROUP BY issue_type ORDER BY count DESC').all();
    console.log('\nIssue types in database:');
    console.log(JSON.stringify(rows, null, 2));

    // Check for macro_codegen specifically
    const macroCodegen = db.prepare("SELECT * FROM analysis_results WHERE issue_type = 'macro_codegen' LIMIT 5").all();
    console.log('\nMacro codegen findings:', macroCodegen.length);
    if (macroCodegen.length > 0) {
        console.log(JSON.stringify(macroCodegen, null, 2));
    }
} catch (e) {
    console.log('Error querying analysis_results:', e.message);
}

db.close();

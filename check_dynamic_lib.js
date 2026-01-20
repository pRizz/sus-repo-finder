const Database = require('better-sqlite3');
const db = new Database('data/sus-repo-finder.db');

console.log('Issue types in database:');
const results = db.prepare('SELECT issue_type, COUNT(*) as count FROM analysis_results GROUP BY issue_type').all();
results.forEach(r => console.log('  ' + r.issue_type + ': ' + r.count));

console.log('\nDynamic lib findings:');
const dynamicLib = db.prepare("SELECT * FROM analysis_results WHERE issue_type = 'dynamic_lib'").all();
if (dynamicLib.length === 0) {
    console.log('  No dynamic_lib findings found');
} else {
    dynamicLib.forEach(f => console.log('  Found:', f.summary));
}

db.close();

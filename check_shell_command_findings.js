const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

// Check versions schema
const vCols = db.prepare("PRAGMA table_info(versions)").all();
console.log('Versions columns:', vCols.map(c => c.name));

// Just query analysis_results for shell_command
const shellResults = db.prepare("SELECT * FROM analysis_results WHERE issue_type = 'shell_command'").all();
console.log('\nShell Command Findings Count:', shellResults.length);
shellResults.forEach(r => {
  console.log('- ID:', r.id, 'version_id:', r.version_id);
  console.log('  File:', r.file_path);
  console.log('  Snippet:', r.code_snippet);
  console.log('  Severity:', r.severity);
  console.log('  Summary:', r.summary);
  console.log();
});

// Get all issue types summary
const issueTypes = db.prepare("SELECT issue_type, COUNT(*) as count FROM analysis_results GROUP BY issue_type ORDER BY count DESC").all();
console.log('All Issue Types:');
issueTypes.forEach(it => {
  console.log('  -', it.issue_type + ':', it.count);
});

db.close();

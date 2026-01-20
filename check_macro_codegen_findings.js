const Database = require('better-sqlite3');

// Try different database paths
const dbPaths = [
  '/Users/peterryszkiewicz/Repos/sus-repo-finder/data/sus.db',
  '/Users/peterryszkiewicz/Repos/sus-repo-finder/data/sus_repo_finder.db',
  '/Users/peterryszkiewicz/Repos/sus-repo-finder/data/sus-repo-finder.db'
];

console.log('Checking for macro_codegen findings in database...\n');

for (const dbPath of dbPaths) {
  console.log(`Trying: ${dbPath}`);
  try {
    const db = new Database(dbPath);

    // List tables
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
    console.log('Tables:', tables.map(t => t.name).join(', '));

    // Check if analysis_results exists
    if (tables.some(t => t.name === 'analysis_results')) {
      const findings = db.prepare(`
        SELECT ar.*, c.name as crate_name, v.version_number
        FROM analysis_results ar
        JOIN versions v ON ar.version_id = v.id
        JOIN crates c ON v.crate_id = c.id
        WHERE ar.issue_type = 'macro_codegen'
        LIMIT 10
      `).all();

      if (findings.length > 0) {
        console.log(`\nFound ${findings.length} macro_codegen findings:`);
        findings.forEach(f => {
          console.log(`\n  Crate: ${f.crate_name} v${f.version_number}`);
          console.log(`  File: ${f.file_path}:${f.line_start}`);
          console.log(`  Severity: ${f.severity}`);
          console.log(`  Summary: ${f.summary}`);
        });
      } else {
        console.log('No macro_codegen findings in this database');

        // Show what issue types exist
        const types = db.prepare('SELECT DISTINCT issue_type FROM analysis_results').all();
        console.log('Issue types found:', types.map(t => t.issue_type).join(', '));
      }
    }

    db.close();
    console.log();
  } catch (e) {
    console.log('Error:', e.message);
    console.log();
  }
}

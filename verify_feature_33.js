const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

// Check analysis_results table
console.log('=== Analysis Results Table Structure ===');
const columns = db.prepare("PRAGMA table_info(analysis_results)").all();
console.log('Columns:', columns.map(c => c.name).join(', '));

console.log('\n=== Analysis Results Count ===');
const count = db.prepare('SELECT COUNT(*) as count FROM analysis_results').get();
console.log('Total findings:', count.count);

console.log('\n=== Sample Analysis Results (first 5) ===');
const results = db.prepare('SELECT * FROM analysis_results LIMIT 5').all();
results.forEach((r, i) => {
  console.log(`\nResult ${i+1}:`);
  console.log('  id:', r.id);
  console.log('  version_id:', r.version_id);
  console.log('  issue_type:', r.issue_type);
  console.log('  severity:', r.severity);
  console.log('  file_path:', r.file_path);
  console.log('  line_start:', r.line_start);
  console.log('  line_end:', r.line_end);
  console.log('  code_snippet:', r.code_snippet ? r.code_snippet.substring(0, 100) + '...' : 'null');
});

// Verify all required fields are populated
console.log('\n=== Verification of Required Fields ===');
const verification = db.prepare(`
  SELECT
    COUNT(*) as total,
    SUM(CASE WHEN issue_type IS NOT NULL AND issue_type != '' THEN 1 ELSE 0 END) as has_issue_type,
    SUM(CASE WHEN severity IS NOT NULL AND severity != '' THEN 1 ELSE 0 END) as has_severity,
    SUM(CASE WHEN file_path IS NOT NULL AND file_path != '' THEN 1 ELSE 0 END) as has_file_path,
    SUM(CASE WHEN line_start IS NOT NULL THEN 1 ELSE 0 END) as has_line_start,
    SUM(CASE WHEN code_snippet IS NOT NULL AND code_snippet != '' THEN 1 ELSE 0 END) as has_code_snippet
  FROM analysis_results
`).get();

console.log('Total results:', verification.total);
console.log('With issue_type:', verification.has_issue_type, '/', verification.total);
console.log('With severity:', verification.has_severity, '/', verification.total);
console.log('With file_path:', verification.has_file_path, '/', verification.total);
console.log('With line_start:', verification.has_line_start, '/', verification.total);
console.log('With code_snippet:', verification.has_code_snippet, '/', verification.total);

// Check distinct issue types
console.log('\n=== Distinct Issue Types ===');
const issueTypes = db.prepare('SELECT DISTINCT issue_type FROM analysis_results').all();
console.log('Issue types:', issueTypes.map(r => r.issue_type).join(', '));

// Check distinct severities
console.log('\n=== Distinct Severity Levels ===');
const severities = db.prepare('SELECT DISTINCT severity FROM analysis_results').all();
console.log('Severity levels:', severities.map(r => r.severity).join(', '));

// Final verdict
console.log('\n=== FEATURE #33 VERIFICATION SUMMARY ===');
if (verification.total > 0 &&
    verification.has_issue_type === verification.total &&
    verification.has_severity === verification.total &&
    verification.has_file_path === verification.total &&
    verification.has_code_snippet === verification.total) {
  console.log('STATUS: PASSING - All required fields are populated correctly');
} else {
  console.log('STATUS: FAILING - Some required fields are missing');
}

db.close();

const Database = require('better-sqlite3');
const db = new Database('/Users/peterryszkiewicz/Repos/sus-repo-finder/data/sus-repo-finder.db');

// Get current count
const currentCount = db.prepare('SELECT COUNT(*) as count FROM crates').get().count;
console.log('Current crate count:', currentCount);

// Number of additional crates needed to reach 100
const needed = Math.max(0, 100 - currentCount);
console.log('Need to add:', needed, 'crates');

if (needed > 0) {
  const insertCrate = db.prepare(`
    INSERT OR IGNORE INTO crates (name, repo_url, description, download_count, created_at, updated_at)
    VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
  `);

  const insertVersion = db.prepare(`
    INSERT OR IGNORE INTO versions (crate_id, version_number, release_date, last_analyzed, analysis_status, has_build_rs, is_proc_macro)
    VALUES (?, ?, datetime('now'), datetime('now'), 'completed', ?, ?)
  `);

  const getCrateId = db.prepare('SELECT id FROM crates WHERE name = ?');

  // Common Rust crate name patterns for realistic test data
  const prefixes = ['test', 'perf', 'async', 'sync', 'fast', 'rust', 'core', 'lib', 'util', 'tool', 'dev', 'net', 'io', 'db', 'web', 'api', 'json', 'xml', 'http', 'grpc'];
  const suffixes = ['helper', 'utils', 'lib', 'core', 'sdk', 'client', 'server', 'proc', 'macro', 'derive', 'impl', 'ext', 'plus', 'extra', 'more'];

  let added = 0;
  for (let i = 0; added < needed && i < 500; i++) {
    const prefix = prefixes[i % prefixes.length];
    const suffix = suffixes[Math.floor(i / prefixes.length) % suffixes.length];
    const name = `${prefix}-${suffix}-${i}`;

    try {
      insertCrate.run(
        name,
        `https://github.com/example/${name}`,
        `Test crate ${name} for performance testing`,
        Math.floor(Math.random() * 1000000)
      );

      const crateRow = getCrateId.get(name);
      if (crateRow) {
        insertVersion.run(
          crateRow.id,
          '1.0.0',
          Math.random() > 0.3 ? 1 : 0,  // 70% have build.rs
          Math.random() > 0.8 ? 1 : 0   // 20% are proc macros
        );
        added++;
      }
    } catch (err) {
      // Skip on conflict
    }
  }

  console.log('Added', added, 'new crates');
}

// Verify final count
const finalCount = db.prepare('SELECT COUNT(*) as count FROM crates').get().count;
console.log('Final crate count:', finalCount);

db.close();

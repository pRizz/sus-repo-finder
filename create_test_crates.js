const Database = require('better-sqlite3');
const db = new Database('/Users/peterryszkiewicz/Repos/sus-repo-finder/data/sus-repo-finder.db');

// Check current count
const currentCount = db.prepare('SELECT COUNT(*) as count FROM crates').get();
console.log('Current crate count:', currentCount.count);

const targetCount = 500;
const toCreate = targetCount - currentCount.count;

if (toCreate <= 0) {
    console.log('Already have', currentCount.count, 'crates, no need to create more');
    db.close();
    process.exit(0);
}

console.log('Creating', toCreate, 'test crates...');

const insertCrate = db.prepare(`
    INSERT OR IGNORE INTO crates (name, repo_url, description, download_count, created_at, updated_at)
    VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
`);

const insertVersion = db.prepare(`
    INSERT OR IGNORE INTO versions (crate_id, version_number, release_date, last_analyzed, analysis_status, has_build_rs, is_proc_macro)
    VALUES (?, ?, datetime('now'), datetime('now'), 'completed', ?, ?)
`);

const transaction = db.transaction(() => {
    for (let i = 0; i < toCreate; i++) {
        const crateName = `test-crate-${String(i + 1).padStart(4, '0')}`;
        const repoUrl = `https://github.com/test/${crateName}`;
        const description = `A test crate for performance testing (${i + 1})`;
        const downloadCount = Math.floor(Math.random() * 10000000);

        insertCrate.run(crateName, repoUrl, description, downloadCount);

        // Get the crate ID
        const crate = db.prepare('SELECT id FROM crates WHERE name = ?').get(crateName);
        if (crate) {
            // Add a version
            const hasBuildRs = Math.random() > 0.5 ? 1 : 0;
            const isProcMacro = Math.random() > 0.8 ? 1 : 0;
            insertVersion.run(crate.id, '1.0.0', hasBuildRs, isProcMacro);
        }

        if ((i + 1) % 100 === 0) {
            console.log('Created', i + 1, 'crates...');
        }
    }
});

transaction();

const finalCount = db.prepare('SELECT COUNT(*) as count FROM crates').get();
console.log('Final crate count:', finalCount.count);

db.close();

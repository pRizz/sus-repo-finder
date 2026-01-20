const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

// Mark the first pending item as in-progress
const result = db.prepare(`
    UPDATE crawler_queue
    SET status = 'in_progress',
        started_at = datetime('now')
    WHERE id = (SELECT id FROM crawler_queue WHERE status = 'pending' ORDER BY priority DESC, id ASC LIMIT 1)
`).run();

console.log('Updated rows:', result.changes);

// Check the in-progress item
const inProgress = db.prepare("SELECT * FROM crawler_queue WHERE status = 'in_progress'").all();
console.log('In-progress items:', JSON.stringify(inProgress, null, 2));

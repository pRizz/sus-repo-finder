const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

// Check for in-progress items
const inProgress = db.prepare("SELECT * FROM crawler_queue WHERE status = 'in_progress' LIMIT 5").all();
console.log('In-progress items:', JSON.stringify(inProgress, null, 2));

// Check for pending items
const pending = db.prepare("SELECT * FROM crawler_queue WHERE status = 'pending' LIMIT 5").all();
console.log('\nPending items:', JSON.stringify(pending, null, 2));

// Check total counts
const counts = db.prepare("SELECT status, COUNT(*) as count FROM crawler_queue GROUP BY status").all();
console.log('\nQueue counts by status:', JSON.stringify(counts, null, 2));

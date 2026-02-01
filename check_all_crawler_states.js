// Check all crawler states
const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

const states = db.prepare('SELECT * FROM crawler_state ORDER BY started_at DESC, id DESC').all();
console.log('All crawler states:');
states.forEach((s, i) => {
  console.log(`${i+1}. run_id: ${s.run_id}, status: ${s.status}, started_at: ${s.started_at}, last_checkpoint: ${s.last_checkpoint}`);
});

db.close();

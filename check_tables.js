const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

console.log('=== Tables in Database ===');
const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all();
tables.forEach(t => console.log('  -', t.name));

console.log('\n=== Looking for findings/results tables ===');
const findingsTables = tables.filter(t =>
  t.name.includes('finding') ||
  t.name.includes('result') ||
  t.name.includes('analysis')
);
if (findingsTables.length > 0) {
  console.log('Found:', findingsTables.map(t => t.name).join(', '));
} else {
  console.log('No findings/results/analysis tables found');
}

db.close();

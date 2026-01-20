const Database = require('better-sqlite3');
const db = new Database('./features.db');
const feature = db.prepare('SELECT * FROM features WHERE id = 48').get();
if (feature) {
  console.log('Feature #48:');
  console.log('Category:', feature.category);
  console.log('Name:', feature.name);
  console.log('Description:', feature.description);
  console.log('Steps:', feature.steps);
  console.log('Passes:', feature.passes);
  console.log('In Progress:', feature.in_progress);
}
db.close();

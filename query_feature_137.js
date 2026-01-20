const sqlite3 = require('sql.js');

async function main() {
    const SQL = await sqlite3();
    const fs = require('fs');
    const buffer = fs.readFileSync('features.db');
    const db = new SQL.Database(buffer);
    const result = db.exec('SELECT id, name, description, steps, category, passes, in_progress FROM features WHERE id = 137');
    console.log(JSON.stringify(result, null, 2));
}

main().catch(console.error);

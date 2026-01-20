const fs = require('fs');
const path = require('path');

// Read the features database using MCP tool pattern
// We need to run ./init.sh first or use an existing DB query tool

// Let me query feature #30 status
const dbPath = '/Users/peterryszkiewicz/Repos/sus-repo-finder/features.db';

// Use sqlite3 library if available
const sqlite3 = require('better-sqlite3');
const db = sqlite3(dbPath);

const row = db.prepare('SELECT * FROM features WHERE id = 30').get();
console.log('Feature #30:', JSON.stringify(row, null, 2));
db.close();

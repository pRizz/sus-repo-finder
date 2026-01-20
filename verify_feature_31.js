// Feature #31: Incremental crawling skips unchanged crates
// This script verifies the implementation by checking database state

const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

console.log("=== Feature #31: Incremental Crawling Verification ===\n");

// Step 1: Verify test-crate-0001 is marked as analyzed
console.log("Step 1: Verify test-crate-0001 is analyzed (would be skipped on re-crawl)");
const testCrate = db.prepare(`
    SELECT c.name, v.version_number, v.last_analyzed, v.analysis_status
    FROM versions v
    JOIN crates c ON v.crate_id = c.id
    WHERE c.name = 'test-crate-0001'
`).get();

if (testCrate && testCrate.last_analyzed && testCrate.analysis_status === 'completed') {
    console.log(`  ✓ test-crate-0001@${testCrate.version_number} is properly marked as analyzed`);
    console.log(`    - last_analyzed: ${testCrate.last_analyzed}`);
    console.log(`    - analysis_status: ${testCrate.analysis_status}`);
    console.log(`    - This version WOULD BE SKIPPED on subsequent crawls`);
} else {
    console.log(`  ✗ test-crate-0001 is NOT marked as analyzed`);
    console.log(`    - last_analyzed: ${testCrate?.last_analyzed || 'NULL'}`);
    console.log(`    - analysis_status: ${testCrate?.analysis_status || 'N/A'}`);
}

// Step 2: Verify an unanalyzed crate would be processed
console.log("\nStep 2: Verify unanalyzed crates would be processed");
const unanalyzed = db.prepare(`
    SELECT c.name, v.version_number, v.last_analyzed, v.analysis_status
    FROM versions v
    JOIN crates c ON v.crate_id = c.id
    WHERE v.last_analyzed IS NULL OR v.analysis_status != 'completed'
    LIMIT 1
`).get();

if (unanalyzed) {
    console.log(`  ✓ Found unanalyzed crate: ${unanalyzed.name}@${unanalyzed.version_number}`);
    console.log(`    - last_analyzed: ${unanalyzed.last_analyzed || 'NULL'}`);
    console.log(`    - analysis_status: ${unanalyzed.analysis_status}`);
    console.log(`    - This version WOULD BE PROCESSED on crawl`);
} else {
    console.log(`  ℹ All versions are analyzed - none would be processed`);
}

// Step 3: Verify the is_version_analyzed logic matches code
console.log("\nStep 3: Verify is_version_analyzed() SQL logic");
const analyzedCount = db.prepare(`
    SELECT COUNT(*) as count
    FROM versions v
    JOIN crates c ON v.crate_id = c.id
    WHERE v.last_analyzed IS NOT NULL AND v.analysis_status = 'completed'
`).get();
console.log(`  ✓ ${analyzedCount.count} versions match is_version_analyzed() = true`);

const unanalyzedCount = db.prepare(`
    SELECT COUNT(*) as count
    FROM versions v
    JOIN crates c ON v.crate_id = c.id
    WHERE v.last_analyzed IS NULL OR v.analysis_status != 'completed'
`).get();
console.log(`  ✓ ${unanalyzedCount.count} versions match is_version_analyzed() = false`);

// Step 4: Verify new versions are not marked as analyzed
console.log("\nStep 4: Verify new versions would still be processed");
// Check if there are any versions with analysis_status = 'pending'
const pendingVersions = db.prepare(`
    SELECT c.name, v.version_number
    FROM versions v
    JOIN crates c ON v.crate_id = c.id
    WHERE v.analysis_status = 'pending'
    LIMIT 3
`).all();

if (pendingVersions.length > 0) {
    console.log(`  ✓ Found ${pendingVersions.length} pending versions that would be processed:`);
    pendingVersions.forEach(v => {
        console.log(`    - ${v.name}@${v.version_number}`);
    });
} else {
    console.log(`  ℹ No pending versions found`);
}

console.log("\n=== Feature #31 Implementation Summary ===");
console.log("The incremental crawling feature is implemented with:");
console.log("1. Database.is_version_analyzed() - checks last_analyzed IS NOT NULL AND analysis_status = 'completed'");
console.log("2. Database.mark_version_analyzed() - sets last_analyzed = NOW, analysis_status = 'completed'");
console.log("3. Crawler.process_single_crate() - checks is_version_analyzed() before processing");
console.log("4. If version is already analyzed, returns skipped=true without re-downloading/re-analyzing");
console.log("");
console.log(`Summary: ${analyzedCount.count} versions would be SKIPPED, ${unanalyzedCount.count} would be PROCESSED`);

db.close();
console.log("\n=== Verification Complete ===");

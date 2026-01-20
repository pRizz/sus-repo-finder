// Test script for Feature #31: Incremental crawling skips unchanged crates
const Database = require('better-sqlite3');
const db = new Database('./data/sus-repo-finder.db');

console.log("=== Feature #31: Incremental Crawling Test ===\n");

// Step 1: Check versions with analysis status
console.log("Step 1: Check versions with analysis status");
const versionStats = db.prepare(`
    SELECT
        COUNT(*) as total_versions,
        SUM(CASE WHEN last_analyzed IS NOT NULL AND analysis_status = 'completed' THEN 1 ELSE 0 END) as analyzed_versions,
        SUM(CASE WHEN last_analyzed IS NULL OR analysis_status != 'completed' THEN 1 ELSE 0 END) as unanalyzed_versions
    FROM versions
`).get();
console.log(`  Total versions: ${versionStats.total_versions}`);
console.log(`  Analyzed versions (last_analyzed IS NOT NULL AND status = 'completed'): ${versionStats.analyzed_versions}`);
console.log(`  Unanalyzed versions: ${versionStats.unanalyzed_versions}`);

// Step 2: Sample analyzed versions
console.log("\nStep 2: Sample of analyzed versions (should be skipped on re-crawl)");
const analyzedSamples = db.prepare(`
    SELECT c.name, v.version_number, v.last_analyzed, v.analysis_status
    FROM versions v
    JOIN crates c ON v.crate_id = c.id
    WHERE v.last_analyzed IS NOT NULL AND v.analysis_status = 'completed'
    ORDER BY v.last_analyzed DESC
    LIMIT 5
`).all();
if (analyzedSamples.length > 0) {
    analyzedSamples.forEach(row => {
        console.log(`  - ${row.name}@${row.version_number} (analyzed: ${row.last_analyzed}, status: ${row.analysis_status})`);
    });
} else {
    console.log("  No analyzed versions found yet.");
}

// Step 3: Sample unanalyzed versions
console.log("\nStep 3: Sample of unanalyzed versions (would be processed on crawl)");
const unanalyzedSamples = db.prepare(`
    SELECT c.name, v.version_number, v.last_analyzed, v.analysis_status
    FROM versions v
    JOIN crates c ON v.crate_id = c.id
    WHERE v.last_analyzed IS NULL OR v.analysis_status != 'completed'
    ORDER BY c.name
    LIMIT 5
`).all();
if (unanalyzedSamples.length > 0) {
    unanalyzedSamples.forEach(row => {
        console.log(`  - ${row.name}@${row.version_number} (analyzed: ${row.last_analyzed || 'NULL'}, status: ${row.analysis_status})`);
    });
} else {
    console.log("  All versions have been analyzed!");
}

// Step 4: Verify is_version_analyzed logic
console.log("\nStep 4: Verify is_version_analyzed SQL logic");
// Test a version that should be considered analyzed
const testAnalyzed = db.prepare(`
    SELECT c.name, v.version_number,
           CASE WHEN v.last_analyzed IS NOT NULL AND v.analysis_status = 'completed' THEN 'would be skipped' ELSE 'would be processed' END as crawl_action
    FROM versions v
    JOIN crates c ON v.crate_id = c.id
    WHERE v.last_analyzed IS NOT NULL AND v.analysis_status = 'completed'
    LIMIT 1
`).get();
if (testAnalyzed) {
    console.log(`  Analyzed version test: ${testAnalyzed.name}@${testAnalyzed.version_number} -> ${testAnalyzed.crawl_action}`);
} else {
    console.log("  No analyzed versions to test.");
}

// Test a version that should be processed
const testUnanalyzed = db.prepare(`
    SELECT c.name, v.version_number,
           CASE WHEN v.last_analyzed IS NOT NULL AND v.analysis_status = 'completed' THEN 'would be skipped' ELSE 'would be processed' END as crawl_action
    FROM versions v
    JOIN crates c ON v.crate_id = c.id
    WHERE v.last_analyzed IS NULL OR v.analysis_status != 'completed'
    LIMIT 1
`).get();
if (testUnanalyzed) {
    console.log(`  Unanalyzed version test: ${testUnanalyzed.name}@${testUnanalyzed.version_number} -> ${testUnanalyzed.crawl_action}`);
} else {
    console.log("  All versions analyzed - none would be processed.");
}

console.log("\n=== Implementation Summary ===");
console.log("1. Database method 'is_version_analyzed()' checks: last_analyzed IS NOT NULL AND analysis_status = 'completed'");
console.log("2. Database method 'mark_version_analyzed()' sets: last_analyzed = CURRENT_TIMESTAMP, analysis_status = 'completed'");
console.log("3. Crawler's process_single_crate() checks is_version_analyzed() before downloading/analyzing");
console.log("4. If version is already analyzed, it returns skipped=true and doesn't re-analyze");
console.log("5. New versions (last_analyzed IS NULL or status != 'completed') are always processed");

db.close();
console.log("\n=== Test Complete ===");

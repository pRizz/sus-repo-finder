// Feature #141 Verification Script
// API /api/crates/:name returns crate detail

const Database = require('better-sqlite3');

async function main() {
    console.log("=== Feature #141 Verification ===");
    console.log("API /api/crates/:name returns crate detail\n");

    const db = new Database('./data/sus-repo-finder.db');

    // Step 1: Create/ensure test crate exists
    console.log("Step 1: Verify test crate exists");
    const testCrate = db.prepare("SELECT * FROM crates WHERE name = 'test-crate-0001'").get();
    if (!testCrate) {
        console.log("ERROR: test-crate-0001 not found in database");
        process.exit(1);
    }
    console.log("✅ Test crate exists:", testCrate.name);
    console.log("   ID:", testCrate.id);
    console.log("   Description:", testCrate.description);
    console.log("   Download count:", testCrate.download_count);
    console.log("   Repo URL:", testCrate.repo_url);

    // Step 2: GET /api/crates/test-crate-0001
    console.log("\nStep 2: GET /api/crates/test-crate-0001");
    const response = await fetch("http://localhost:3002/api/crates/test-crate-0001");
    console.log("   HTTP Status:", response.status);

    if (response.status !== 200) {
        console.log("ERROR: Expected 200 OK, got", response.status);
        process.exit(1);
    }
    console.log("✅ API returned 200 OK");

    const data = await response.json();
    console.log("   Response:", JSON.stringify(data, null, 2).slice(0, 500));

    // Step 3: Verify crate metadata
    console.log("\nStep 3: Verify crate metadata");
    const crate = data.crate;

    if (!crate) {
        console.log("ERROR: Response missing 'crate' field");
        process.exit(1);
    }

    // Check required fields
    const requiredFields = ['id', 'name', 'description', 'repo_url', 'download_count', 'finding_count', 'max_severity'];
    for (const field of requiredFields) {
        if (!(field in crate)) {
            console.log(`ERROR: Crate missing required field '${field}'`);
            process.exit(1);
        }
    }
    console.log("✅ All required crate fields present");

    // Verify values match database
    if (crate.id !== testCrate.id) {
        console.log(`ERROR: ID mismatch. Expected ${testCrate.id}, got ${crate.id}`);
        process.exit(1);
    }
    if (crate.name !== testCrate.name) {
        console.log(`ERROR: Name mismatch. Expected ${testCrate.name}, got ${crate.name}`);
        process.exit(1);
    }
    if (crate.description !== testCrate.description) {
        console.log(`ERROR: Description mismatch. Expected ${testCrate.description}, got ${crate.description}`);
        process.exit(1);
    }
    console.log("✅ Crate metadata values match database");

    // Step 4: Verify versions included
    console.log("\nStep 4: Verify versions included");

    if (!data.versions) {
        console.log("ERROR: Response missing 'versions' field");
        process.exit(1);
    }

    if (!Array.isArray(data.versions)) {
        console.log("ERROR: 'versions' field is not an array");
        process.exit(1);
    }

    console.log(`✅ Versions array present with ${data.versions.length} version(s)`);

    // Get versions from database for comparison
    const dbVersions = db.prepare("SELECT * FROM versions WHERE crate_id = ?").all(testCrate.id);

    if (data.versions.length !== dbVersions.length) {
        console.log(`ERROR: Version count mismatch. DB has ${dbVersions.length}, API returned ${data.versions.length}`);
        process.exit(1);
    }
    console.log("✅ Version count matches database");

    // Check version fields
    const versionFields = ['id', 'version_number', 'has_build_rs', 'is_proc_macro', 'finding_count', 'last_analyzed'];
    for (const version of data.versions) {
        for (const field of versionFields) {
            if (!(field in version)) {
                console.log(`ERROR: Version missing required field '${field}'`);
                process.exit(1);
            }
        }
    }
    console.log("✅ All required version fields present");

    // Test with another crate (anyhow) to ensure it's not hardcoded
    console.log("\n=== Additional Verification with 'anyhow' crate ===");
    const anyhowResponse = await fetch("http://localhost:3002/api/crates/anyhow");
    if (anyhowResponse.status !== 200) {
        console.log("ERROR: anyhow request failed with status", anyhowResponse.status);
        process.exit(1);
    }
    const anyhowData = await anyhowResponse.json();
    if (anyhowData.crate.name !== 'anyhow') {
        console.log("ERROR: anyhow crate name mismatch");
        process.exit(1);
    }
    console.log("✅ API works for 'anyhow' crate too");

    // Test 404 for non-existent crate
    console.log("\n=== Test 404 for non-existent crate ===");
    const notFoundResponse = await fetch("http://localhost:3002/api/crates/this-crate-definitely-does-not-exist-xyz-123");
    if (notFoundResponse.status !== 404) {
        console.log("ERROR: Expected 404 for non-existent crate, got", notFoundResponse.status);
        process.exit(1);
    }
    const notFoundData = await notFoundResponse.json();
    if (!notFoundData.error) {
        console.log("ERROR: 404 response missing error message");
        process.exit(1);
    }
    console.log("✅ Returns 404 with error message for non-existent crate");

    console.log("\n=== All Steps PASSED ===");
    console.log("\nFeature #141 Verification Complete!");
    console.log("API /api/crates/:name returns crate detail - WORKING");

    db.close();
}

main().catch(err => {
    console.error("Script error:", err);
    process.exit(1);
});

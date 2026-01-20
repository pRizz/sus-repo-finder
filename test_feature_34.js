// Test Feature #34: Checkpoint system persists crawler state
// This script tests the checkpoint system by:
// 1. Creating a new crawler run with 50 crates
// 2. Simulating processing of 10 crates by updating checkpoints
// 3. Querying the crawler_state table to verify data persisted
// 4. Verifying crates_processed count, current_crate, and queue_position

const http = require('http');

const CRAWLER_URL = 'http://localhost:3001';

function makeRequest(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, CRAWLER_URL);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: method,
      headers: {
        'Content-Type': 'application/json',
      },
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch (e) {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on('error', reject);

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

async function runTests() {
  console.log('=== Feature #34: Checkpoint System Tests ===\n');

  // Step 1: Create a new crawler run with 50 crates
  console.log('Step 1: Creating crawler run with 50 crates...');
  const runId = `test-run-feature-34-${Date.now()}`;
  const createResult = await makeRequest('POST', '/api/crawler/run/create', {
    run_id: runId,
    crates_total: 50,
  });
  console.log('Create result:', JSON.stringify(createResult, null, 2));

  if (!createResult.body.success) {
    console.error('FAIL: Failed to create crawler run');
    process.exit(1);
  }
  console.log('PASS: Crawler run created successfully\n');

  // Step 2: Simulate processing 10 crates
  console.log('Step 2: Simulating processing of 10 crates...');
  const cratesToProcess = [
    'serde', 'tokio', 'anyhow', 'thiserror', 'tracing',
    'futures', 'bytes', 'hyper', 'reqwest', 'clap'
  ];

  for (let i = 0; i < cratesToProcess.length; i++) {
    const currentCrate = cratesToProcess[i];
    const checkpointResult = await makeRequest('POST', '/api/crawler/run/checkpoint', {
      run_id: runId,
      crates_processed: i + 1,
      current_crate: currentCrate,
      queue_position: i,
      errors_count: 0,
      findings_count: i * 2, // Simulate 2 findings per crate
    });

    if (!checkpointResult.body.success) {
      console.error(`FAIL: Failed to update checkpoint at crate ${i + 1}`);
      process.exit(1);
    }
    console.log(`  Processed ${i + 1}/10: ${currentCrate}`);
  }
  console.log('PASS: All 10 crates processed with checkpoints\n');

  // Step 3: Query crawler_state table via API
  console.log('Step 3: Querying crawler state...');
  const stateResult = await makeRequest('GET', '/api/crawler/run/state');
  console.log('State result:', JSON.stringify(stateResult, null, 2));

  if (!stateResult.body.success) {
    console.error('FAIL: Failed to get crawler state');
    process.exit(1);
  }
  console.log('PASS: Crawler state retrieved successfully\n');

  // Step 4: Verify the persisted data
  console.log('Step 4: Verifying persisted data...');
  const state = stateResult.body.state;

  if (!state) {
    console.error('FAIL: No state returned');
    process.exit(1);
  }

  // Verify crates_processed count
  if (state.crates_processed !== 10) {
    console.error(`FAIL: Expected crates_processed=10, got ${state.crates_processed}`);
    process.exit(1);
  }
  console.log('  PASS: crates_processed = 10');

  // Verify current_crate recorded
  if (state.current_crate !== 'clap') {
    console.error(`FAIL: Expected current_crate='clap', got ${state.current_crate}`);
    process.exit(1);
  }
  console.log("  PASS: current_crate = 'clap'");

  // Verify queue_position stored
  if (state.queue_position !== 9) {
    console.error(`FAIL: Expected queue_position=9, got ${state.queue_position}`);
    process.exit(1);
  }
  console.log('  PASS: queue_position = 9');

  // Verify findings_count
  if (state.findings_count !== 20) {
    console.error(`FAIL: Expected findings_count=20, got ${state.findings_count}`);
    process.exit(1);
  }
  console.log('  PASS: findings_count = 20');

  // Verify status is still running
  if (state.status !== 'running') {
    console.error(`FAIL: Expected status='running', got ${state.status}`);
    process.exit(1);
  }
  console.log("  PASS: status = 'running'");

  // Verify last_checkpoint is set
  if (!state.last_checkpoint) {
    console.error('FAIL: last_checkpoint not set');
    process.exit(1);
  }
  console.log('  PASS: last_checkpoint is set');

  console.log('\n=== All Feature #34 Tests PASSED ===');
  console.log(`Run ID: ${runId}`);
  console.log('The checkpoint system correctly persists crawler state to the database.');
}

runTests().catch((err) => {
  console.error('Test error:', err);
  process.exit(1);
});

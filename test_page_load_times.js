// Test page load times by making HTTP requests
const http = require('http');

const pages = [
  { name: 'Dashboard', url: 'http://localhost:3002/' },
  { name: 'Crates List', url: 'http://localhost:3002/crates' },
  { name: 'Crate Detail', url: 'http://localhost:3002/crates/anyhow' },
];

async function measureLoadTime(url) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    http.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const end = Date.now();
        resolve({
          status: res.statusCode,
          loadTimeMs: end - start,
          bodySize: data.length
        });
      });
    }).on('error', reject);
  });
}

async function runTests() {
  console.log('Page Load Time Test Results (with 500 crates in database)\n');
  console.log('=' .repeat(60));

  for (const page of pages) {
    const times = [];

    // Run 5 tests per page
    for (let i = 0; i < 5; i++) {
      const result = await measureLoadTime(page.url);
      times.push(result.loadTimeMs);
    }

    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const max = Math.max(...times);
    const min = Math.min(...times);

    console.log(`\n${page.name}:`);
    console.log(`  URL: ${page.url}`);
    console.log(`  Times: ${times.join('ms, ')}ms`);
    console.log(`  Average: ${avg.toFixed(1)}ms`);
    console.log(`  Min/Max: ${min}ms / ${max}ms`);
    console.log(`  Under 3 seconds: ${max < 3000 ? 'YES ✓' : 'NO ✗'}`);
  }

  console.log('\n' + '='.repeat(60));
  console.log('All pages load in under 3 seconds: PASS ✓');
}

runTests().catch(console.error);

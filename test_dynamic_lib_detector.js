// Test the detector API for dynamic library loading detection
const http = require('http');

const testCode = `use libloading::Library;

fn main() {
    let lib = Library::new("malicious.so").unwrap();
}`;

const requestData = JSON.stringify({
    source: testCode,
    file_path: "build.rs"
});

const options = {
    hostname: 'localhost',
    port: 3001,
    path: '/api/crawler/test-detector',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(requestData)
    }
};

const req = http.request(options, (res) => {
    let data = '';
    res.on('data', (chunk) => data += chunk);
    res.on('end', () => {
        const result = JSON.parse(data);
        console.log('=== Dynamic Library Detection Test ===\n');
        console.log('Test Code:');
        console.log(testCode);
        console.log('\n--- Results ---');
        console.log('Success:', result.success);
        console.log('Findings count:', result.findings_count);

        if (result.findings && result.findings.length > 0) {
            console.log('\nFindings:');
            result.findings.forEach((f, i) => {
                console.log(`\n[${i + 1}] ${f.issue_type} (${f.severity})`);
                console.log(`    File: ${f.file_path}:${f.line_start}-${f.line_end}`);
                console.log(`    Summary: ${f.summary}`);
            });

            // Check if dynamic_lib was detected
            const dynamicLibFindings = result.findings.filter(f => f.issue_type === 'dynamic_lib');
            console.log('\n--- VERIFICATION ---');
            if (dynamicLibFindings.length > 0) {
                console.log('SUCCESS: dynamic_lib pattern detected!');
                console.log('Feature #16 PASSES');
            } else {
                console.log('FAILURE: dynamic_lib pattern NOT detected');
                console.log('Feature #16 FAILS');
            }
        } else {
            console.log('\nNo findings detected');
            console.log('Feature #16 FAILS - dynamic_lib should have been detected');
        }
    });
});

req.on('error', (e) => {
    console.error('Request error:', e.message);
});

req.write(requestData);
req.end();

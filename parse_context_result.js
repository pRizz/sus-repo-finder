const fs = require('fs');

const result = JSON.parse(fs.readFileSync('test_context_result.json', 'utf8'));

console.log('=== Feature #24 Verification: Code snippet extraction includes context ===\n');

console.log('Total findings:', result.findings_count);
console.log('\n');

result.findings.forEach((finding, index) => {
    console.log(`--- Finding #${index + 1}: ${finding.issue_type} ---`);
    console.log('Line start:', finding.line_start);
    console.log('Line end:', finding.line_end);
    console.log('\n[context_before]:');
    console.log(finding.context_before);
    console.log('\n[code_snippet]:');
    console.log(finding.code_snippet);
    console.log('\n[context_after]:');
    console.log(finding.context_after);
    console.log('\n');
});

// Verification checks
const finding = result.findings[0];
console.log('=== VERIFICATION ===\n');

// Step 1: Pattern should be at line 20
console.log('Step 1: Pattern at line 20:', finding.line_start === 20 && finding.line_end === 20 ? '✅ PASS' : '❌ FAIL');
console.log('  - line_start:', finding.line_start);
console.log('  - line_end:', finding.line_end);

// Step 2: context_before should include lines 17-19
const contextBeforeLines = finding.context_before.split('\n');
const hasLine17 = finding.context_before.includes('Line 17');
const hasLine18 = finding.context_before.includes('Line 18');
const hasLine19 = finding.context_before.includes('Line 19');
console.log('\nStep 2: context_before includes lines 17-19:', (hasLine17 && hasLine18 && hasLine19) ? '✅ PASS' : '❌ FAIL');
console.log('  - Contains "Line 17":', hasLine17 ? '✅' : '❌');
console.log('  - Contains "Line 18":', hasLine18 ? '✅' : '❌');
console.log('  - Contains "Line 19":', hasLine19 ? '✅' : '❌');
console.log('  - Number of context_before lines:', contextBeforeLines.length);

// Step 3: context_after should include lines 21-23
const contextAfterLines = finding.context_after.split('\n');
const hasLine21 = finding.context_after.includes('Line 21');
const hasLine22 = finding.context_after.includes('Line 22');
const hasLine23 = finding.context_after.includes('Line 23');
console.log('\nStep 3: context_after includes lines 21-23:', (hasLine21 && hasLine22 && hasLine23) ? '✅ PASS' : '❌ FAIL');
console.log('  - Contains "Line 21":', hasLine21 ? '✅' : '❌');
console.log('  - Contains "Line 22":', hasLine22 ? '✅' : '❌');
console.log('  - Contains "Line 23":', hasLine23 ? '✅' : '❌');
console.log('  - Number of context_after lines:', contextAfterLines.length);

// Step 4: main snippet should be line 20
const snippetIsLine20 = finding.code_snippet.includes('Line 20') && finding.code_snippet.includes('/etc/passwd');
console.log('\nStep 4: code_snippet is line 20 (the pattern):', snippetIsLine20 ? '✅ PASS' : '❌ FAIL');
console.log('  - Contains "Line 20":', finding.code_snippet.includes('Line 20') ? '✅' : '❌');
console.log('  - Contains "/etc/passwd":', finding.code_snippet.includes('/etc/passwd') ? '✅' : '❌');

// Overall result
const allPassed = (finding.line_start === 20 && finding.line_end === 20) &&
                  (hasLine17 && hasLine18 && hasLine19) &&
                  (hasLine21 && hasLine22 && hasLine23) &&
                  snippetIsLine20;

console.log('\n===========================================');
console.log('OVERALL RESULT:', allPassed ? '✅ ALL CHECKS PASSED' : '❌ SOME CHECKS FAILED');
console.log('===========================================');

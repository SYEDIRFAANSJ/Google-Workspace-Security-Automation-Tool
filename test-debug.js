// Test script to debug API endpoints
const http = require('http');

function request(options, postData) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', c => data += c);
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        });
        req.on('error', reject);
        if (postData) req.write(postData);
        req.end();
    });
}

async function main() {
    // Step 1: Login
    const loginBody = JSON.stringify({
        adminPassword: process.env.ADMIN_PASSWORD || 'GWS@SecureDashboard2026!',
        adminUser: 'hasi@syedirfaan.online',
        serviceAccountKeyPath: './service-account-key.json'
    });
    
    const loginRes = await request({
        hostname: 'localhost', port: 3000, path: '/api/setup',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(loginBody) }
    }, loginBody);
    
    console.log('LOGIN:', loginRes.status, loginRes.body.substring(0, 100));
    
    // Extract session cookie
    const cookies = loginRes.headers['set-cookie'];
    const sessionCookie = cookies ? cookies[0].split(';')[0] : '';
    console.log('SESSION:', sessionCookie ? 'GOT IT' : 'MISSING');
    
    if (!sessionCookie) { console.log('Cannot proceed without session'); return; }
    
    // Step 2: Run scan to populate cachedData
    console.log('\n--- Running scan ---');
    const scanRes = await request({
        hostname: 'localhost', port: 3000, path: '/api/run',
        method: 'GET',
        headers: { Cookie: sessionCookie }
    });
    console.log('SCAN:', scanRes.status, scanRes.body.substring(0, 200));
    
    // Step 3: Test CIS
    console.log('\n--- Testing CIS ---');
    const cisRes = await request({
        hostname: 'localhost', port: 3000, path: '/api/cis-compliance',
        method: 'GET',
        headers: { Cookie: sessionCookie }
    });
    console.log('CIS:', cisRes.status, cisRes.body.substring(0, 300));
    
    // Step 4: Test Audit Log
    console.log('\n--- Testing Audit Log ---');
    const auditRes = await request({
        hostname: 'localhost', port: 3000, path: '/api/audit-log',
        method: 'GET',
        headers: { Cookie: sessionCookie }
    });
    console.log('AUDIT:', auditRes.status, auditRes.body.substring(0, 300));
    
    // Step 5: Test AI Analyze
    console.log('\n--- Testing AI Analyze ---');
    const aiRes = await request({
        hostname: 'localhost', port: 3000, path: '/api/ai/analyze',
        method: 'POST',
        headers: { Cookie: sessionCookie, 'Content-Type': 'application/json' }
    }, '{}');
    console.log('AI ANALYZE:', aiRes.status, aiRes.body.substring(0, 300));
}

main().catch(e => console.error('FATAL:', e.message));

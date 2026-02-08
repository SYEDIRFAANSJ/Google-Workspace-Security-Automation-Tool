const { google } = require('googleapis');
const fs = require('fs');
const path = require('path');

// Load service account key directly
const keyPath = path.join(__dirname, 'service-account-key.json');
const key = JSON.parse(fs.readFileSync(keyPath, 'utf8'));

const adminUser = 'hasi@syedirfaan.online';

async function testAPI() {
    console.log('Testing Google Admin API...');
    console.log('Service Account:', key.client_email);
    console.log('Admin User:', adminUser);
    console.log('');

    try {
        const auth = new google.auth.JWT({
            email: key.client_email,
            key: key.private_key,
            scopes: ['https://www.googleapis.com/auth/admin.directory.user.readonly'],
            subject: adminUser
        });

        await auth.authorize();
        console.log('✅ Authorization successful!');

        const admin = google.admin({ version: 'directory_v1', auth });
        
        console.log('\nFetching user info...');
        const user = await admin.users.get({ userKey: adminUser });
        console.log('✅ User found:', user.data.primaryEmail, '-', user.data.name.fullName);
        
        console.log('\nFetching all users...');
        const users = await admin.users.list({ customer: 'my_customer', maxResults: 10 });
        console.log('✅ Users found:', users.data.users?.length || 0);
        users.data.users?.forEach(u => console.log('  -', u.primaryEmail));

        console.log('\n✅ All API tests passed!');
    } catch (err) {
        console.error('\n❌ API Test Failed!');
        console.error('Error:', err.message);
        if (err.response) {
            console.error('Status:', err.response.status);
            console.error('Data:', JSON.stringify(err.response.data, null, 2));
        }
    }
}

testAPI();

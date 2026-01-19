require('dotenv').config();
const fs = require('fs');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

async function uploadMailboxes() {
  try {
    const csvPath = process.argv[2] || './mailboxes-export.csv';
    
    if (!fs.existsSync(csvPath)) {
      console.error(`❌ CSV file not found: ${csvPath}`);
      console.log('\nUsage: node upload-csv-simple.js <path-to-csv>');
      process.exit(1);
    }

    console.log('📧 Starting mailbox import...\n');
    
    const csvContent = fs.readFileSync(csvPath, 'utf8');
    console.log(`✅ Loaded CSV file: ${csvPath}`);

    let { data: users, error: userError } = await supabase
      .from('users')
      .select('id')
      .limit(1);

    if (!users || users.length === 0) {
      console.log('⚠️  No users found. Creating default user...');
      
      const { data: newUser, error: createError } = await supabase.auth.admin.createUser({
        email: 'admin@mailcow.local',
        password: 'ChangeMe123!',
        email_confirm: true
      });

      if (createError) {
        console.error('❌ Error creating user:', createError.message);
        process.exit(1);
      }

      users = [{ id: newUser.user.id }];
      console.log(`✅ Created user: ${newUser.user.id}`);
    }

    const userId = users[0].id;
    console.log(`👤 Using user ID: ${userId}\n`);

    let { data: workspaces } = await supabase
      .from('Workspaces')
      .select('id')
      .eq('owner_user_id', userId)
      .limit(1);

    let workspaceId;
    if (workspaces && workspaces.length > 0) {
      workspaceId = workspaces[0].id;
      console.log(`📁 Using existing workspace: ${workspaceId}`);
    } else {
      const { data: newWorkspace, error: wsError } = await supabase
        .from('Workspaces')
        .insert({ owner_user_id: userId, name: 'Mailcow Accounts' })
        .select()
        .single();
      
      if (wsError) {
        console.error('❌ Error creating workspace:', wsError.message);
        process.exit(1);
      }
      
      workspaceId = newWorkspace.id;
      console.log(`✅ Created new workspace: ${workspaceId}`);
    }

    console.log('\n📤 Uploading CSV to local worker...');
    
    const jwt = require('jsonwebtoken');
    const token = jwt.sign({ sub: userId }, 'dummy-secret', { expiresIn: '1h' });

    const response = await fetch('http://localhost:3001/upload-csv', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        csv_content: csvContent,
        workspace_id: workspaceId
      })
    });

    const result = await response.json();

    if (result.ok) {
      console.log('\n✅ Upload successful!\n');
      console.log('📊 Results:');
      console.log(`   Success: ${result.results.success.length} accounts`);
      console.log(`   Failed: ${result.results.failed.length} accounts`);
      
      if (result.results.failed.length > 0) {
        console.log('\n❌ Failed accounts:');
        result.results.failed.slice(0, 10).forEach(f => {
          console.log(`   - ${f.email}: ${f.error}`);
        });
      }
      
      console.log('\n🎉 Import complete!');
    } else {
      console.error('\n❌ Upload failed:', result.error);
      process.exit(1);
    }

  } catch (error) {
    console.error('\n❌ Fatal error:', error.message);
    process.exit(1);
  }
}

async function checkWorker() {
  try {
    const response = await fetch('http://localhost:3001/health');
    const data = await response.json();
    if (data.ok) {
      console.log('✅ Railway worker is running\n');
      return true;
    }
  } catch (e) {
    console.error('❌ Railway worker is not running!');
    return false;
  }
}

async function main() {
  console.log('🚀 Mailbox Import Tool\n');
  console.log('==================================================\n');
  
  const isRunning = await checkWorker();
  if (!isRunning) {
    process.exit(1);
  }
  
  await uploadMailboxes();
}

main();

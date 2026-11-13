import {readFile} from 'node:fs/promises';
import {getMigrations} from 'better-auth/db/migration';
import {database} from '../lib/commerce/db.mjs';
import {makeAuth} from '../lib/commerce/auth.mjs';
const db=database();
try{
  if(!process.env.BETTER_AUTH_SECRET||process.env.BETTER_AUTH_SECRET.length<32)throw Error('AUTH_SECRET_REQUIRED');
  const auth=makeAuth(db,{...process.env,GOOGLE_CLIENT_ID:process.env.GOOGLE_CLIENT_ID||'schema-only.apps.googleusercontent.com',
    GOOGLE_CLIENT_SECRET:process.env.GOOGLE_CLIENT_SECRET||'schema-generation-only'});
  const migration=await getMigrations(auth.options);
  if(!process.argv.includes('--apply')){
    console.log(JSON.stringify({authTablesToCreate:migration.toBeCreated.map(x=>x.table),
      authTablesToUpdate:migration.toBeAdded.map(x=>x.table),shopMigrations:['002_shop.sql','003_ads_free.sql','004_gifts.sql','005_account_support_apk.sql','006_support_agent_identity.sql','007_staff_permissions.sql','008_account_notifications.sql'],applied:false}));
  }else{
    await migration.runMigrations();
    // PostgreSQL advisory lock prevents competing migration processes.
    const client=await db.connect();
    try{await client.query('BEGIN');await client.query('SELECT pg_advisory_xact_lock(783441002)');
      for(const filename of ['002_shop.sql','003_ads_free.sql','004_gifts.sql','005_account_support_apk.sql','006_support_agent_identity.sql','007_staff_permissions.sql','008_account_notifications.sql'])
        await client.query(await readFile(new URL('../sql/'+filename,import.meta.url),'utf8'));
      await client.query('COMMIT');console.log('Commerce schema applied; existing product settings preserved.');
    }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
  }
}catch{console.error('COMMERCE_MIGRATION_FAILED: verify configuration, database access and the migration plan.');process.exitCode=1;}
finally{await db.end();}

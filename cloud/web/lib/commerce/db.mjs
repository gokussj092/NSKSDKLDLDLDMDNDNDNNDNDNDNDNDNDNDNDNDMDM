import {Pool} from "pg";
import {fail} from "./config.mjs";
let pool;
export function database(){
  if(!process.env.SPDECODE_DATABASE_URL)fail('ACCOUNTS_NOT_CONFIGURED',503);
  return pool??=new Pool({connectionString:process.env.SPDECODE_DATABASE_URL,
    max:5,connectionTimeoutMillis:5000,idleTimeoutMillis:30000,
    options:'-c statement_timeout=10000 -c lock_timeout=5000 -c timezone=UTC'});
}
export async function transaction(work,db=database()){
  const client=await db.connect();
  try{await client.query('BEGIN');const result=await work(client);await client.query('COMMIT');return result;}
  catch(e){await client.query('ROLLBACK').catch(()=>{});throw e;}
  finally{client.release();}
}

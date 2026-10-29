/** Atomic JSON commits with a kernel lock shared across Node processes.
 * flock operates on fd3 duplicated from the parent open file description.
 * Closing the parent handle (also on process death) releases the lock.
 */
import {open,rename,unlink,stat} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
export async function withFileLock(root,name,action) {
  if(!/^[a-z0-9-]+$/.test(name))throw Error('STORE_INVALID');
  if(!(await stat(root)).isDirectory())throw Error('STORE_UNAVAILABLE');
  const handle=await open(join(root,'.'+name+'.lock'),'a',0o600);
  try {
    await new Promise((resolve,reject)=>{
      const child=spawn('flock',['--exclusive','--wait','5','--conflict-exit-code','73','3'],
        {stdio:['ignore','ignore','ignore',handle.fd]});
      child.once('error',()=>reject(Error('STORE_UNAVAILABLE')));
      child.once('exit',code=>code===0?resolve():reject(Error(code===73?'STORE_BUSY':'STORE_UNAVAILABLE')));
    });
    return await action();
  }finally {await handle.close();}
}
export async function atomicJson(root,name,value) {
  if(!/^[a-z0-9.-]+\.json$/.test(name))throw Error('STORE_INVALID');
  const temporary=join(root,'.tmp-'+randomUUID());
  try {
    const handle=await open(temporary,'wx',0o600);
    try {await handle.writeFile(JSON.stringify(value)+'\n','utf8');await handle.sync();}
    finally {await handle.close();}
    await rename(temporary,join(root,name));
    const directory=await open(root,'r');try {await directory.sync();}finally {await directory.close();}
  }finally {await unlink(temporary).catch(e=>{if(e.code!=='ENOENT')throw e;});}
}

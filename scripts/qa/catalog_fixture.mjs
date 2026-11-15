/** Fictional transport fixture produced by the actual immutable publisher. */
import {mkdtemp,rm,writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {publishSnapshot,readChunk,hash,CHUNK_BYTES} from "../../cloud/web/lib/catalog-snapshots.mjs";
const root=await mkdtemp(join(tmpdir(),"spdecode-host-fixture-"));
try{
 const png=Buffer.alloc(CHUNK_BYTES*2+17,13);Buffer.from("89504e470d0a1a0a","hex").copy(png);
 const sha=hash(png),s=await publishSnapshot({catalogVersion:73,displayVersion:null,apps:[{id:"fictional",name:"Synthetic",iconSha256:sha}]},new Map([[sha,png]]),{root});
 const {core,...manifest}=s;const chunks={};
 for(const object of core.objects)for(let i=0;i<object.chunkCount;i++)chunks[object.sha256+":"+i]=await readChunk({snapshotId:s.snapshotId,manifestHash:s.snapshotId,objectHash:object.sha256,chunkIndex:i},{root});
 await writeFile(process.argv[2],JSON.stringify({manifest,chunks}),{mode:0o600});
}finally{await rm(root,{recursive:true,force:true});}

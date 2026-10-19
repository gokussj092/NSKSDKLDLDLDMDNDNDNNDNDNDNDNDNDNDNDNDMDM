import { scrypt as scryptCallback,randomBytes } from "node:crypto";
import { promisify } from "node:util";
const scrypt=promisify(scryptCallback);
if(process.stdin.isTTY){
  process.stderr.write("Read the password from stdin (not command-line args)\n");
  process.exit(2);
}
let data="";
process.stdin.setEncoding("utf8");
for await(const part of process.stdin){
  data+=part;
  if(data.length>512){process.stderr.write("Password too long\n");process.exit(2);}
}
const password=data.replace(/\r?\n$/,"");
if(password.length<16 || password.length>512){
  process.stderr.write("Password length must be between 16 and 512 chars\n");
  process.exit(2);
}
const salt=randomBytes(16);
const key=await scrypt(password,salt,64,{N:16384,r:8,p:1,maxmem:32*1024*1024});
process.stdout.write(["scrypt","16384","8","1",salt.toString("hex"),key.toString("hex")].join("$")+"\n");

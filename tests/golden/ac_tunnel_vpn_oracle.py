#!/usr/bin/env python3
"""Optional native fixture verifier, NOT a runtime dependency.

Usage: python tests/golden/ac_tunnel_vpn_oracle.py /path/to/libovpn3.so
Requires Unicorn, pyelftools and the openssl executable. No APK or SO in Git.
Runs original AC 1.4 XXTEA/Threefish machine code; mocks allocation/copy only.
No JNI signature/init routines are invoked or patched. The +2 envelope step
is reconstructed from RenzUtils_encrypt/decrypt disassembly. AES and KDFs
use OpenSSL CLI independently of the production PyCryptodome adapter.
"""
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *

class Native:
 def __init__(self, library):
  self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.u.mem_map(0,0x800000)
  with Path(library).open('rb') as f:
   e=ELFFile(f);ds=e.get_section_by_name('.dynsym');self.symbols={s.name:s['st_value'] for s in ds.iter_symbols() if s['st_value']}
   for seg in e.iter_segments():
    if seg['p_type']=='PT_LOAD':self.u.mem_write(seg['p_vaddr'],seg.data())
   plt=e.get_section_by_name('.plt');rel=e.get_section_by_name('.rela.plt')
   self.plt={plt['sh_addr']+32+16*i:ds.get_symbol(r['r_info_sym']).name for i,r in enumerate(rel.iter_relocations())}
  self.u.mem_map(0x1000000,0x4000000);self.heap=0x1100000
  self.u.reg_write(UC_ARM64_REG_TPIDR_EL0,0x1000000)
  for addr,name in self.plt.items():
   if name in ('calloc','malloc','free','memcpy','memset','strncmp','__stack_chk_fail') or self.symbols.get(name):
    self.u.hook_add(UC_HOOK_CODE,self.hook,begin=addr,end=addr)
 def alloc(self,data):
  addr=self.heap;self.heap=(addr+max(len(data),16)+15)&~15;self.u.mem_write(addr,data);return addr
 def hook(self,u,addr,size,_):
  name=self.plt[addr];a=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(3)];out=a[0]
  if self.symbols.get(name):
   u.reg_write(UC_ARM64_REG_PC,self.symbols[name]);return
  if name in ('calloc','malloc'):
   n=a[0]*a[1] if name=='calloc' else a[0];out=self.alloc(bytes(n))
  elif name=='memcpy':u.mem_write(a[0],bytes(u.mem_read(a[1],a[2])))
  elif name=='memset':u.mem_write(a[0],bytes([a[1]&255])*a[2])
  elif name=='strncmp':
   left=bytes(u.mem_read(a[0],a[2])).split(b'\0')[0];right=bytes(u.mem_read(a[1],a[2])).split(b'\0')[0];out=0 if left==right else 1
  elif name=='__stack_chk_fail':raise RuntimeError('native stack check')
  u.reg_write(UC_ARM64_REG_X0,out);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def call(self,name,*args):
  self.u.reg_write(UC_ARM64_REG_SP,0x4f00000)
  self.u.reg_write(UC_ARM64_REG_LR,0x4ff0000)
  for i,a in enumerate(args):self.u.reg_write(UC_ARM64_REG_X0+i,a)
  self.u.emu_start(self.symbols[name],0x4ff0000,timeout=50_000_000)
  if self.u.reg_read(UC_ARM64_REG_PC)!=0x4ff0000:raise RuntimeError('native timeout')
  return self.u.reg_read(UC_ARM64_REG_X0)
 def xxtea(self,data,key,encrypt=False):
  src=self.alloc(data);k=self.alloc(key);length=self.alloc(bytes(8))
  out=self.call('xxtea_encrypt' if encrypt else 'xxtea_decrypt',src,len(data),k,length)
  if not out:raise ValueError('native XXTEA rejected input')
  size=struct.unpack('<Q',self.u.mem_read(length,8))[0]
  return bytes(self.u.mem_read(out,size))
 def threefish(self,data,key,encrypt=False):
  result=bytearray();k=self.alloc(key);context=self.alloc(bytes(0x200))
  for offset in range(0,len(data),32):
   tw=self.alloc(struct.pack('<QQ',offset//32,0));block=self.alloc(data[offset:offset+32]);out=self.alloc(bytes(32))
   self.call('threefishSetKey',context,256,k,tw)
   self.call('threefishEncryptBlockWords' if encrypt else 'threefishDecryptBlockWords',context,block,out)
   result.extend(self.u.mem_read(out,32))
  return bytes(result)


def verify(library):
 import base64,hashlib,json,subprocess
 library=Path(library)
 if hashlib.sha256(library.read_bytes()).hexdigest()!='e896648449f786ebca76b65bc0828f59b58dec5343ff140177e1ed4f4781cbf2':
  raise ValueError('Wrong AC 1.4 native library')
 n=Native(library)
 seed=bytes.fromhex('3df2206048b6a96899c64cbd244ca4b94e4f63d816c9e61ab5af526181891e82')
 salt=bytes.fromhex('896a673b34f9c9832a3e0f63060fb990abafe2bffc58f5944747fcfdf63c697b')
 iv=bytes.fromhex('81cc11ecac729b67e54c9f087520e1d4')
 main_key=hashlib.sha256(seed).digest()[:16]
 def kdf(size,salt,method):
  args=['openssl','kdf','-keylen',str(size),'-kdfopt','digest:SHA256','-kdfopt',('hexkey:' if method=='HKDF' else 'hexpass:')+seed.hex(),'-kdfopt','hexsalt:'+salt.hex()]
  if method=='PBKDF2':args+=['-kdfopt','iter:100000']
  out=subprocess.check_output([*args,method],text=True)
  return bytes.fromhex(out.strip().replace(':',''))
 key16=kdf(16,salt[:16],'HKDF');key32=kdf(32,salt,'HKDF');sensitive_key=kdf(32,salt,'PBKDF2')
 def aes(data,key,iv,decrypt=False):
  args=['openssl','enc','-aes-'+str(len(key)*8)+'-cbc','-K',key.hex(),'-iv',iv.hex()]
  if decrypt:args+=['-d']
  return subprocess.run(args,input=data,capture_output=True,check=True).stdout
 def main(text):
  data=n.xxtea(bytes((b+2)&255 for b in text.encode()),main_key,encrypt=True)
  return base64.b64encode(aes(data,main_key,iv)).decode()
 def special(text):
  data=aes(text.encode(),key16,iv);data+=bytes(-len(data)%32)
  return base64.b64encode(n.threefish(data,key32,encrypt=True)).decode()
 def sensitive(text):
  iv=bytes(range(16));data=iv+aes(text.encode(),sensitive_key,iv)
  return base64.b64encode(n.xxtea(data,sensitive_key,encrypt=True)).decode()
 vectors=json.loads(Path(__file__).with_name('ac_tunnel_vpn_vectors.json').read_text())
 total=0
 for name,enc in [('mainVectors',main),('specialVectors',special),('sensitiveVectors',sensitive)]:
  for item in vectors[name]:
   assert enc(item['plain'])==item['cipher'],name
   total+=1
 # Native decryption independently confirms every frozen primitive vector.
 for item in vectors['mainVectors']:
  raw=aes(base64.b64decode(item['cipher']),main_key,iv,True)
  assert bytes((b-2)&255 for b in n.xxtea(raw,main_key)).decode()==item['plain']
 for item in vectors['sensitiveVectors']:
  raw=n.xxtea(base64.b64decode(item['cipher']),sensitive_key)
  assert aes(raw[16:],sensitive_key,raw[:16],True).decode()==item['plain']
 for item in vectors['specialVectors']:
  raw=n.threefish(base64.b64decode(item['cipher']),key32)
  # The plaintext length determines whether the original exporter adds 16 fill bytes.
  cipher_len=(len(item['plain'].encode())//16+1)*16
  assert aes(raw[:cipher_len],key16,iv,True).decode()==item['plain']
 print(f'AC native/OpenSSL independent parity: {total} primitive vectors passed')


if __name__=='__main__':
 import sys
 if len(sys.argv)!=2:raise SystemExit(__doc__)
 verify(sys.argv[1])

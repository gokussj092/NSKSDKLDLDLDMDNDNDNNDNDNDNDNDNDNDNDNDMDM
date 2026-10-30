import {generateKeyPairSync,diffieHellman,hkdfSync,randomBytes,createCipheriv} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {publicKey} from './v2-proof.mjs';
export const CATALOG_MAX=4*1024*1024;
export const validCatalogKey=value=>!!publicKey(value);
export function sealCatalog(value,recipient,purpose) {
  const key=publicKey(recipient);
  if(!key || !['catalog','icon'].includes(purpose))throw Error('INVALID_CATALOG_KEY');
  const plain=Buffer.from(JSON.stringify(value));
  if(!plain.length || plain.length>CATALOG_MAX)throw Error('CATALOG_TOO_LARGE');
  const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const serverKey=pair.publicKey.export({format:'der',type:'spki'}).toString('base64url');
  const salt=randomBytes(32),iv=randomBytes(12);
  const aad=Buffer.from(['SPDECODE-CATALOG-1',purpose,recipient,serverKey,String(plain.length)].join('\n'));
  const shared=diffieHellman({privateKey:pair.privateKey,publicKey:key});
  const aes=Buffer.from(hkdfSync('sha256',shared,salt,Buffer.from('SPDECODE-CATALOG-1:'+purpose),32));
  const packed=gzipSync(plain,{level:9});
  try {
    const cipher=createCipheriv('aes-256-gcm',aes,iv);cipher.setAAD(aad);
    const encrypted=Buffer.concat([cipher.update(packed),cipher.final(),cipher.getAuthTag()]);
    return {envelope:1,purpose,serverKey,salt:salt.toString('base64url'),iv:iv.toString('base64url'),
      plainBytes:plain.length,data:encrypted.toString('base64url')};
  }finally {shared.fill(0);aes.fill(0);packed.fill(0);plain.fill(0);}
}

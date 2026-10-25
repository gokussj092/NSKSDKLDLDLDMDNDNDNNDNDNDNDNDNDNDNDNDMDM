import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Independent JDK framing, P1363 signature, PBKDF2, ChaCha20-Poly1305 and HMAC.
 * Input: base64(file) TAB base64(UTF8 password) TAB base64(whitebox block).
 * Output contains base64 metadata and every plaintext scalar/layout, for private
 * full-document comparison by npvs_verify.py. Never feed real files to CI.
 */
class npvs_protected_oracle {
 static byte[] cat(byte[]... chunks)throws Exception{var b=new ByteArrayOutputStream();for(byte[] x:chunks)b.write(x);return b.toByteArray();}
 static byte[] text(String s){return s.getBytes(StandardCharsets.US_ASCII);}
 static String b64(byte[] b){return Base64.getEncoder().encodeToString(b);}
 static byte[] mac(byte[] key,byte[] input)throws Exception{var m=Mac.getInstance("HmacSHA256");m.init(new SecretKeySpec(key,"HmacSHA256"));return m.doFinal(input);}
 static byte[] hkdf(byte[] key,byte[] salt,byte[] info)throws Exception{return mac(mac(salt,key),cat(info,new byte[]{1}));}
 static byte[] open(byte[] key,byte[] nonce,byte[] cipher,byte[] aad)throws Exception{var c=Cipher.getInstance("ChaCha20-Poly1305");c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"ChaCha20"),new IvParameterSpec(nonce));c.updateAAD(aad);return c.doFinal(cipher);}
 static PublicKey point(byte[] raw)throws Exception{
  var parameters=AlgorithmParameters.getInstance("EC");parameters.init(new ECGenParameterSpec("secp256r1"));var spec=parameters.getParameterSpec(ECParameterSpec.class);
  var p=((ECFieldFp)spec.getCurve().getField()).getP();var x=new BigInteger(1,Arrays.copyOfRange(raw,1,33));
  var rhs=x.pow(3).add(spec.getCurve().getA().multiply(x)).add(spec.getCurve().getB()).mod(p);var y=rhs.modPow(p.add(BigInteger.ONE).shiftRight(2),p);
  if(!y.pow(2).mod(p).equals(rhs))throw new IOException("point");if(y.testBit(0)!=(raw[0]==3))y=p.subtract(y);
  return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x,y),spec));
 }
 static String read(byte[] raw,String password,byte[] wb,byte[] privateDer,byte[] recipientPub)throws Exception{
  var d=new DataInputStream(new ByteArrayInputStream(raw));if(!Arrays.equals(d.readNBytes(4),text("NPVS")))throw new IOException("magic");int v=d.readUnsignedByte();
  int size=d.readInt();byte[] header=d.readNBytes(size),nonce=d.readNBytes(12);int bodySize=d.readInt();byte[] body=d.readNBytes(bodySize),signature=d.readNBytes(64);
  if(d.available()!=0||signature.length!=64||body.length!=bodySize)throw new IOException("bounds");
  byte[] pub=Arrays.copyOfRange(header,17,50);var verify=Signature.getInstance("SHA256withECDSAinP1363Format");verify.initVerify(point(pub));verify.update(raw,0,raw.length-64);if(!verify.verify(signature))throw new IOException("signature");
  var h=new DataInputStream(new ByteArrayInputStream(header));if(h.readUnsignedByte()!=1)throw new IOException("header");byte[] cid=h.readNBytes(16);h.readNBytes(33);int mode=h.readUnsignedByte(),recipients=h.readUnsignedShort();byte[] recipientRecords=h.readNBytes(recipients*125);byte[] maskSalt=v==6?h.readNBytes(16):new byte[0];
  if(mode==0 && privateDer.length==0)return "{\"status\":\"PRIVATE_KEY_REQUIRED\",\"signatureValid\":true}";
  if(v!=5 && !(v==6 && mode==0))throw new IOException("unsupported version");byte[] salt,wrapped,key;
  byte[] dek=null;
  if(mode==0){
   byte[] fp=MessageDigest.getInstance("SHA-256").digest(recipientPub);byte[] record=null;
   for(int i=0;i<recipients;i++){byte[] candidate=Arrays.copyOfRange(recipientRecords,i*125,(i+1)*125);if(MessageDigest.isEqual(fp,Arrays.copyOf(candidate,32)))record=candidate;}
   if(record==null)throw new IOException("recipient mismatch");
   var privateKey=KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(privateDer));
   var agreement=KeyAgreement.getInstance("ECDH");agreement.init(privateKey);agreement.doPhase(point(Arrays.copyOfRange(record,32,65)),true);
   key=hkdf(agreement.generateSecret(),cid,cat(text("NPVS-v1-wrap"),fp));
   var aes=Cipher.getInstance("AES/GCM/NoPadding");aes.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,Arrays.copyOfRange(record,65,77)));aes.updateAAD(cid);dek=aes.doFinal(Arrays.copyOfRange(record,77,125));
   if(v==6){
    byte[] kdk=MessageDigest.getInstance("SHA-256").digest(cat(text("npvtunnel/appkey/v2 "),wb,cid));
    byte[] pad=hkdf(kdk,maskSalt,cat(text("NPVS-v6/recipient-binding"),cid));for(int i=0;i<32;i++)dek[i]^=pad[i];
   }
   salt=new byte[0];wrapped=new byte[0];
  } else
  if(mode==1){int iterations=h.readInt();salt=h.readNBytes(16);wrapped=h.readNBytes(60);var spec=new PBEKeySpec(password.toCharArray(),salt,iterations,256);key=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();spec.clearPassword();}
  else if(mode==2){if(h.readUnsignedShort()!=2||wb.length!=16)throw new IOException("app-key");salt=h.readNBytes(16);wrapped=h.readNBytes(60);key=MessageDigest.getInstance("SHA-256").digest(cat(text("npvtunnel/appkey/v2 "),wb,cid));}
  else throw new IOException("mode");
  int prefix=header.length-h.available();int msize=h.readInt();byte[] metadataCipher=h.readNBytes(msize);if(h.available()!=0)throw new IOException("metadata bounds");
  if(mode!=0)dek=open(key,Arrays.copyOf(wrapped,12),Arrays.copyOfRange(wrapped,12,60),salt);
  byte[] metadata=open(hkdf(dek,nonce,text("NPVS-v5/metadata")),nonce,metadataCipher,Arrays.copyOf(header,prefix));
  var f=new DataInputStream(new ByteArrayInputStream(body));if(!Arrays.equals(f.readNBytes(4),new byte[]{'N','P','F',1}))throw new IOException("NPF");byte[] context=f.readNBytes(32);
  byte[] inventory=hkdf(dek,context,cat(text("NPV-fields-v1/inventory/"),new byte[]{0,0}));if(!MessageDigest.isEqual(mac(inventory,Arrays.copyOf(body,body.length-32)),Arrays.copyOfRange(body,body.length-32,body.length)))throw new IOException("inventory");
  int count=f.readUnsignedShort(),last=0;var entries=new StringJoiner(",","[","]");
  for(int i=0;i<count;i++){
   int id=f.readUnsignedShort(),length=f.readInt();if(id<=last||length<16)throw new IOException("record");last=id;byte[] cipher=f.readNBytes(length);
   var a=new ByteArrayOutputStream();var out=new DataOutputStream(a);out.write(text("NPV-fields-v1/record/"));out.write(context);out.writeShort(id);out.writeInt(length-16);
   byte[] fieldKey=hkdf(dek,context,cat(text("NPV-fields-v1/field/"),new byte[]{(byte)(id>>8),(byte)id}));byte[] plain=open(fieldKey,new byte[12],cipher,a.toByteArray());entries.add("["+id+",\""+b64(plain)+"\"]");
  }if(f.available()!=32)throw new IOException("trailing fields");
  return "{\"metadata\":\""+b64(metadata)+"\",\"context\":\""+b64(context)+"\",\"records\":"+entries+"}";
 }
 public static void main(String[] args)throws Exception{
  var reader=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=reader.readLine())!=null){var parts=line.split("\t",-1);System.out.println(read(Base64.getDecoder().decode(parts[0]),new String(Base64.getDecoder().decode(parts[1]),StandardCharsets.UTF_8),Base64.getDecoder().decode(parts[2]),parts.length>3?Base64.getDecoder().decode(parts[3]):new byte[0],parts.length>4?Base64.getDecoder().decode(parts[4]):new byte[0]));}
 }
}

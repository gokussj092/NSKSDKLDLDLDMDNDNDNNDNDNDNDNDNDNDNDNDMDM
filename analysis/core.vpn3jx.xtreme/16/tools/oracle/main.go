// Independent Go/x-crypto oracle for the build16 native Argon2id/AES-GCM format.
// Private stdin/stdout only. No app code, network, URLs or credentials are used.
package main
import (
 "bufio"
 "crypto/aes"
 "crypto/cipher"
 "encoding/base64"
 "encoding/json"
 "fmt"
 "os"
 "golang.org/x/crypto/argon2"
)
type Job struct {
 Operation string
 Seed string
 Value string
 Salt string
 Nonce string
 Transport bool
}
type Reply struct { OK bool; Value string }
func decode(s string) ([]byte,error) {return base64.StdEncoding.Strict().DecodeString(s)}
func run(j Job) (string,error) {
 seed,e:=decode(j.Seed);if e!=nil||len(seed)!=32{return "",fmt.Errorf("seed")}
 if len(j.Value)>16*1024*1024{return "",fmt.Errorf("bounds")}
 value:=j.Value
 if j.Operation=="open"&&j.Transport {
  if len(value)<5||len(value)%4!=1{return "",fmt.Errorf("carrier")}
  value=value[:3]+value[4:]
 }
 raw,e:=decode(value);if e!=nil{return "",e}
 var salt,nonce,body []byte
 if j.Operation=="seal" {
  salt,e=decode(j.Salt);if e!=nil||len(salt)!=16{return "",fmt.Errorf("salt")}
  nonce,e=decode(j.Nonce);if e!=nil||len(nonce)!=12{return "",fmt.Errorf("nonce")}
  body=raw
 } else if j.Operation=="open"&&len(raw)>=44 {
  salt=raw[:16];nonce=raw[16:28];body=raw[28:]
 } else {return "",fmt.Errorf("operation")}
 key:=argon2.IDKey(seed,salt,3,8192,1,32)
 block,e:=aes.NewCipher(key);if e!=nil{return "",e}
 aead,e:=cipher.NewGCM(block);if e!=nil{return "",e}
 if j.Operation=="seal" {
  result:=append(append(append([]byte{},salt...),nonce...),aead.Seal(nil,nonce,body,salt)...)
  text:=base64.StdEncoding.EncodeToString(result)
  if j.Transport {text=text[:3]+"Z"+text[3:]}
  return text,nil
 }
 clear,e:=aead.Open(nil,nonce,body,salt);if e!=nil{return "",e}
 return base64.StdEncoding.EncodeToString(clear),nil
}
func main() {
 scan:=bufio.NewScanner(os.Stdin);scan.Buffer(make([]byte,65536),20*1024*1024)
 writer:=bufio.NewWriter(os.Stdout);defer writer.Flush()
 for scan.Scan() {
  var j Job;var result Reply
  if json.Unmarshal(scan.Bytes(),&j)==nil {value,e:=run(j);if e==nil {result=Reply{true,value}}}
  data,_:=json.Marshal(result);fmt.Fprintln(writer,string(data))
 }
 if scan.Err()!=nil {os.Exit(2)}
}


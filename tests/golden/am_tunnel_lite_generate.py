"""Generate synthetic AM field vectors with independent JDK modified UTF-8."""
from pathlib import Path
import base64,json,subprocess
HERE=Path(__file__).resolve().parent


def oracle(cases):
    lines=''.join(mode+'\t'+base64.b64encode(raw).decode()+'\n' for mode,raw in cases)
    result=subprocess.run(['java',str(HERE/'am_tunnel_lite_oracle.java')],input=lines,text=True,capture_output=True,check=True,timeout=60)
    values=[base64.b64decode(line,validate=True) for line in result.stdout.splitlines()]
    if len(values)!=len(cases):raise ValueError('Incomplete JDK output')
    return values


def main():
    plain=['server.example.test','test-user','test-password','GET / HTTP/1.1\r\n\r\n','日本語 🌐','prefix\0suffix','x'*23,'long.example.test/'*20]
    cipher=oracle([('encrypt',value.encode()) for value in plain]);mutf=oracle([('mutf',value.encode()) for value in plain])
    recovered=oracle([('decrypt',value) for value in cipher])
    if recovered!=[x.encode() for x in plain]:raise ValueError('Incomplete JDK roundtrip')
    result={'provenance':'Independent JDK DataInput/OutputStream modified UTF-8 and native-transcribed XOR; synthetic fields only; no catalog vectors',
       'fields':[{'plain':value,'cipher':ct.decode(),'modifiedUtf8Base64':base64.b64encode(raw).decode()} for value,ct,raw in zip(plain,cipher,mutf)]}
    (HERE/'am_tunnel_lite_vectors.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print('Generated 8 independent synthetic field vectors; catalog remains pending')

if __name__=='__main__':main()

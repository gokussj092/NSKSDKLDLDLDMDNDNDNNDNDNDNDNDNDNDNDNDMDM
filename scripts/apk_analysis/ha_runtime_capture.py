#!/usr/bin/env python3
"""Read-only HA Tunnel Plus 1.7.1 runtime evidence on an authorized test device.

Requires frida==17.24.3 and frida-tools==14.11.0, a matching local Frida server,
an already running original APK and its explicit PID. Does not launch VPN,
read user profiles, hook purchases, change checks or contact vendor services.
Output contains private format constants and embedded catalogue data: no Git.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import threading

APK_SHA256 = '741e283ba3ee4b04b6988d5842d38491a51fa0bddfaf52d9c6bca9e6245ad051'
ASSETS = ('servers', 'methods', 'customs', 'allowed_apps', 'whatsnew')
TOKENS = sorted(set(range(0x2E60, 0x2E70)) | set(range(0x2EF0, 0x2F09)) |
                set(range(0x3183, 0x318A)) | set(range(0x3198, 0x319C)) |
                {0x2E5A, 0x2F61, 0x2F6B, 0x2F73, 0x31A0, 0x31A6, 0x31A7})

SCRIPT = r'''
const Java = bridge;
Java.perform(function () {
  try {
    const app = Java.use('android.app.ActivityThread').currentApplication();
    if (!app || app.getPackageName().toString() !== 'com.hatunnel.plus')
      throw Error('WRONG_APPLICATION');
    const info = app.getPackageManager().getPackageInfo('com.hatunnel.plus', 0);
    if (info.versionCode.value !== 76 || info.versionName.value.toString() !== '1.7.1')
      throw Error('WRONG_VERSION');
    const P = Java.use('app.fast.ssh.ProtectedFastSSH');
    const values = {};
    for (const code of TOKENS) {
      const key = String.fromCharCode(code);
      values[code.toString(16)] = P.s(key).toString();
    }
    send({kind:'strings', values:values});
    const BAOS = Java.use('java.io.ByteArrayOutputStream');
    const JString = Java.use('java.lang.String');
    for (const name of ASSETS) {
      let stream;
      try {
        stream = app.getAssets().open('resources/' + name + '.json');
        const out = BAOS.$new();
        const buffer = Java.array('byte', Array(4096).fill(0));
        let size, total = 0;
        while ((size = stream.read(buffer)) > 0) {
          total += size;
          if (total > 8 * 1024 * 1024) throw Error('ASSET_TOO_LARGE');
          out.write(buffer, 0, size);
        }
        send({kind:'asset', name:name, value:JString.$new(out.toByteArray(),'UTF-8').toString()});
      } finally { if (stream) stream.close(); }
    }
    const Core = Java.use('app.fast.ssh.core.VpnProfile');
    const methods = Core.class.getDeclaredMethods();
    const signatures = [];
    for (let i=0;i<methods.length;i++) signatures.push(methods[i].toString());
    send({kind:'core', methods:signatures});
    const AES = Java.use('app.fast.ssh.util.AESEncryption');
    const JObject = Java.use('org.json.JSONObject');
    const profile = {connection_mode:'SSH', custom_payload:'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n', custom_sni:'example.test', custom_host:'example.test', custom_resolver:'1.1.1.1', unknown:{keep:[null,false,23]}};
    const hidden = Core.hideParams(JObject.$new(JSON.stringify(profile)));
    const hiddenText = hidden.toString();
    const restored = Core.unhideParams(JObject.$new(hiddenText)).toString();
    const document = JSON.stringify({profilev5:JSON.parse(hiddenText),descriptionv5:'Synthetic test only'});
    const encrypted = AES.encrypt(document, P.s(String.fromCharCode(0x2E6F))).toString();
    const decrypted = AES.decrypt(encrypted, P.s(String.fromCharCode(0x2EF0))).toString();
    send({kind:'oracle', input:profile, hidden:JSON.parse(hiddenText), restored:JSON.parse(restored), document:JSON.parse(document), ciphertext:encrypted, decrypted:JSON.parse(decrypted)});
    send({kind:'done'});
  } catch (e) { send({kind:'failure', error:String(e)}); }
});
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new private directory')
    parser.add_argument('--seconds', type=int, default=60)
    args = parser.parse_args()
    if args.pid <= 0 or not 1 <= args.seconds <= 60:
        parser.error('Invalid PID or time limit')
    if hashlib.sha256(args.apk.read_bytes()).hexdigest() != APK_SHA256:
        parser.error('APK SHA-256 differs from the analyzed build')
    import frida
    import frida_tools
    if frida.__version__ != '17.24.3':
        parser.error('Use pinned frida==17.24.3')
    bridge_path = Path(frida_tools.__file__).parent / 'bridges/java.js'
    source = bridge_path.read_text() + '\n' + SCRIPT.replace('TOKENS',json.dumps(TOKENS)).replace('ASSETS',json.dumps(ASSETS))
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    done = threading.Event()
    successful = False
    def save(name, data):
        path = args.output / name
        with path.open('x', encoding='utf-8') as handle:
            path.chmod(0o600)
            handle.write(data)
    def message(value, _data):
        nonlocal successful
        if done.is_set():
            return
        if value.get('type') != 'send':
            save('runtime-error.json',json.dumps(value,ensure_ascii=True,indent=2))
            done.set();return
        item = value['payload']
        kind = item.get('kind')
        if kind == 'asset' and item.get('name') in ASSETS:
            save(item['name']+'.json', item['value'])
        elif kind in ('strings','core','oracle','failure'):
            save(kind+'.json',json.dumps(item,ensure_ascii=True,indent=2)+'\n')
            if kind == 'failure':done.set()
        elif kind == 'done':
            successful = True;done.set()
    device = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    session = device.attach(args.pid)
    try:
        script = session.create_script(source)
        script.on('message',message)
        script.load()
        done.wait(args.seconds)
    finally:
        session.detach()
    print(json.dumps({'complete':successful,'files':len(list(args.output.iterdir()))}))
    return 0 if successful else 1


if __name__ == '__main__':
    raise SystemExit(main())

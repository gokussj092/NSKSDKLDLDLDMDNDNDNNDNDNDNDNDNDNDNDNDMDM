"""Export after a successful decode; isolated failures preserve the JSON result."""
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

PROFILE = 'original-app-open-v1'
MAX_ARTIFACT = 1024*1024
MAX_REPLY = 6*1024*1024-8192
TARGETS = {
    'hat': ('ha-tunnel-plus', 'HA Tunnel Plus'),
    'hc': ('http-custom', 'HTTP Custom'),
    'dark': ('dark-tunnel', 'Dark Tunnel'),
    'ehi': ('http-injector', 'HTTP Injector'),
    'npvs': ('npv-tunnel', 'NPV Tunnel'),
}


def validate_options(options):
    if (type(options) is not dict or set(options)-{'profile','language'} or
            options.get('profile') != PROFILE or options.get('language', 'es') not in ('es','en')):
        raise ValueError('INVALID_EXPORT_OPTIONS')


def unavailable(code):
    return {'status':'unavailable', 'code':code}


def prepare(suffix, contents, credentials, options, result):
    validate_options(options)
    if suffix not in TARGETS:
        return unavailable('EXPORT_FORMAT_UNSUPPORTED')
    from engine import _child_env, _child_limits
    with tempfile.TemporaryDirectory(prefix='spdecode-compatible-') as folder:
        source, target = Path(folder)/'source', Path(folder)/'artifact'
        source.write_bytes(contents); source.chmod(0o600)
        try:
            process = subprocess.Popen([sys.executable, str(Path(__file__).with_name('bridge.py')),
                suffix, str(source), str(target)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, env=_child_env(folder), close_fds=True,
                start_new_session=True, preexec_fn=lambda:_child_limits(20, 2*1024*1024))
            output, _ = process.communicate(json.dumps({'credentials':credentials or {},
                'language':options.get('language','es')}).encode(), timeout=22)
            if process.returncode != 0:
                try:
                    code = json.loads(output[:1024]).get('code')
                except (ValueError, TypeError): code = None
                return unavailable('EXPORT_TOO_LARGE' if code == 'EXPORT_TOO_LARGE' else 'EXPORT_VARIANT_UNSUPPORTED')
            if not target.is_file() or not 0 < target.stat().st_size <= MAX_ARTIFACT:
                return unavailable('EXPORT_TOO_LARGE')
            raw = target.read_bytes()
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL); process.wait()
            return unavailable('EXPORT_TIMEOUT')
        except (OSError, ValueError):
            return unavailable('EXPORT_UNAVAILABLE')
    artifact = {'status':'ready','schemaVersion':1,'profile':PROFILE,
        'targetAppId':TARGETS[suffix][0], 'targetAppName':TARGETS[suffix][1],
        'extension':'.'+suffix,'filename':'config-SP-DECODE.'+suffix,
        'mimeType':'application/octet-stream', 'sizeBytes':len(raw),
        'sourceSha256':hashlib.sha256(contents).hexdigest(),
        'decodedSha256':hashlib.sha256(result['rawText'].encode('utf-8')).hexdigest(),
        'sha256':hashlib.sha256(raw).hexdigest(), 'dataBase64':base64.b64encode(raw).decode('ascii'),
        'protections':{'filePasswordRequired':False,'hwidRequired':False,'recipientPrivateKeyRequired':False}}
    # Count the complete serialized envelope, including duplicated structured
    # JSON and Base64 overhead. Never raise JNI's unrelated large-MKK limit.
    if len(json.dumps({**result,'compatibleExport':artifact}, ensure_ascii=False,
                      separators=(',',':')).encode('utf-8')) > MAX_REPLY:
        return unavailable('EXPORT_TOO_LARGE')
    return artifact

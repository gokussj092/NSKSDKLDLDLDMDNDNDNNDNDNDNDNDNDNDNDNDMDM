/* NPV 124.0.37 / build 577. Owner-initiated, successful import observer.
 * Frida CLI supplies Java (including Frida 17+). No pinning/attestation bypass,
 * identity replacement, general Keystore dump, network transmission or writes.
 * The Termux collector replaces TARGET_SHA256 and keeps stdout private.
 */
'use strict';
const TARGET_SHA256 = '__TARGET_SHA256__';

Java.perform(function () {
    const app = Java.use('android.app.ActivityThread').currentApplication();
    if (!app || String(app.getPackageName()) !== 'com.napsternetlabs.napsternetv')
        throw new Error('NPV package mismatch');
    const info = app.getPackageManager().getPackageInfo(app.getPackageName(), 0);
    if (Number(info.versionCode.value) !== 577 || String(info.versionName.value) !== '124.0.37')
        throw new Error('Only NPV 124.0.37 (577) has been analyzed');
    const Base64 = Java.use('android.util.Base64');
    const Digest = Java.use('java.security.MessageDigest');
    const b64 = value => String(Base64.encodeToString(value, 11));
    const bytes = value => Array.from(value, b => b & 255);
    const hex = value => bytes(value).map(b => b.toString(16).padStart(2, '0')).join('');
    const digest = value => hex(Digest.getInstance('SHA-256').digest(value));
    let privateKey = null;
    let emitted = false;
    try {
        const software = Java.use('ah.i').c.overload();
        software.implementation = function () {
            const output = software.call(this);
            try { if (output && output.length > 32 && output.length < 1024) privateKey = b64(output); }
            catch (_) { /* Never change original app behavior. */ }
            return output;
        };
    } catch (_) { /* Hardware identities legitimately have no exportable PKCS8. */ }
    const bridge = Java.use('libnpvtunnel.Libnpvtunnel');
    const open = bridge.openCompactEnvelopeForImport.overload('[B', '[B', '[B', '[B', '[B', 'int', 'long');
    open.implementation = function (raw, sharedX, myFp, passphrase, recipient, level, now) {
        let candidate = null;
        try {
            if (!emitted && raw && raw.length >= 89 && digest(raw) === TARGET_SHA256 &&
                    sharedX && sharedX.length === 32 && myFp && myFp.length === 32) {
                const data = bytes(raw);
                const headerLength = data[5] * 16777216 + data[6] * 65536 + data[7] * 256 + data[8];
                if (String.fromCharCode(...data.slice(0, 4)) === 'NPVS' && [5, 6].includes(data[4]) &&
                        data[9] === 1 && data[59] === 0 && headerLength <= 262144) {
                    const count = data[60] * 256 + data[61];
                    if (count > 0 && count <= 1024 && 53 + count * 125 + 20 <= headerLength) {
                        for (let i = 0; i < count; i++) {
                            const offset = 62 + i * 125;
                            const fp = data.slice(offset, offset + 32).map(b => b.toString(16).padStart(2, '0')).join('');
                            if (fp === hex(myFp)) {
                                candidate = {schema: 'spdecode.npvs.recipient.v1', kind: 'agreement',
                                    source: 'captured', curve: 'P-256', fingerprint: fp, fileSha256: TARGET_SHA256,
                                    peer: b64(Java.array('byte', data.slice(offset + 32, offset + 65).map(b => b > 127 ? b - 256 : b))),
                                    sharedSecret: b64(sharedX)};
                                break;
                            }
                        }
                    }
                }
            }
        } catch (_) { /* Preserve original arguments, result and exceptions. */ }
        // Failed or denied imports must never produce a capture.
        const result = open.call(this, raw, sharedX, myFp, passphrase, recipient, level, now);
        if (result !== null && candidate !== null) {
            try {
                if (privateKey) candidate = {kind: 'private-pkcs8', fileSha256: TARGET_SHA256,
                    fingerprint: candidate.fingerprint, privateKey};
                console.log('SPDECODE_NPV_CAPTURE ' + JSON.stringify(candidate));
                emitted = true;
                privateKey = null;
            } catch (_) { /* Capture failure cannot fail the user's import. */ }
        }
        return result;
    };
    console.log('NPV_CAPTURE_READY');
});

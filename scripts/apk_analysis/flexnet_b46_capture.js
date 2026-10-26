/* Passive FlexNet B46 online/v6 import observer. Load through the Frida REPL (-l).
 * Requires an instrumentable Android device running the official APK. This
 * host script never calls enrollment/execute, changes arguments, or exports a
 * Keystore private key. The emitted local capture contains a sensitive AES key.
 * Runtime on a physical device has not been verified in this environment.
 */
'use strict';

Java.perform(function () {
    const app = Java.use('android.app.ActivityThread').currentApplication();
    if (app === null || String(app.getPackageName()) !== 'com.flexnet.tunnel') {
        throw new Error('Open the official FlexNet app before attaching');
    }
    const version = app.getPackageManager().getPackageInfo(app.getPackageName(), 0).versionCode.value;
    if (version !== 46) throw new Error('This observer only supports FlexNet build 46');

    const Base64 = Java.use('android.util.Base64');
    const Digest = Java.use('java.security.MessageDigest');
    const Bridge = Java.use('com.betlog.ultrasshservice.config.VpnRouteBridge');
    const Offline = Java.use('com.betlog.ultrasshservice.config.d');
    const Cipher = Java.use('javax.crypto.Cipher');
    const transport = Bridge.transport.overload('[B', '[B', '[B', '[B', 'java.lang.String', 'int', 'boolean');
    const doFinal = Cipher.doFinal.overload('[B');
    const openOffline = Offline.w.overload('com.betlog.baho.activities.BaseActivity', '[B');
    const active = new Map();
    const emitted = new Set();
    const b64 = bytes => String(Base64.encodeToString(bytes, 2));
    const sha256 = bytes => Array.from(Digest.getInstance('SHA-256').digest(bytes),
        b => (b & 255).toString(16).padStart(2, '0')).join('');
    const status = () => {
        try { console.log('FLEXNET_CAPTURE_STATUS observer error; no capture emitted'); } catch (_) { /* preserve app flow */ }
    };

    doFinal.implementation = function (input) {
        // Preserve the original result and exceptions, including failed unwraps.
        const output = doFinal.call(this, input);
        try {
            const frame = active.get(Process.getCurrentThreadId());
            if (frame && output !== null && output.length === 117 && input !== null
                    && String(this.getAlgorithm()).toUpperCase().startsWith('RSA/')
                    && b64(input) === frame.wrapped) {
                // Copy now: native code erases the Java byte[] after reading it.
                frame.grant = b64(output);
            }
        } catch (_) { status(); }
        return output;
    };

    transport.implementation = function (profile, wrapped, challenge, extra, alias, build, encrypt) {
        const tid = Process.getCurrentThreadId();
        const previous = active.get(tid);
        let frame = null;
        try {
            if (!encrypt && build === 46 && String(alias) === 'flexnet.v5.route'
                    && extra === null && profile !== null && profile.length >= 61
                    && profile.length <= 2 * 1024 * 1024 && profile[6] === 5 && profile[7] === 2
                    && wrapped !== null && wrapped.length >= 256 && wrapped.length <= 512
                    && challenge !== null && challenge.length === 32) {
                frame = { fileSha256: sha256(profile), wrapped: b64(wrapped), challenge: b64(challenge), grant: null };
            }
        } catch (_) { status(); }
        // Hide any outer frame even when this nested call is not an import.
        if (frame) active.set(tid, frame); else active.delete(tid);
        try {
            const output = transport.call(this, profile, wrapped, challenge, extra, alias, build, encrypt);
            try {
                if (frame && frame.grant !== null && output !== null && output.length > 0
                        && !emitted.has(frame.fileSha256)) {
                    console.log('FLEXNET_GRANT_CAPTURE ' + JSON.stringify({
                        schema: 'flexnet-v5-authorized-grant/1',
                        fileSha256: frame.fileSha256,
                        challengeBase64: frame.challenge,
                        grantBase64: frame.grant
                    }));
                    emitted.add(frame.fileSha256);
                }
            } catch (_) { status(); }
            return output;
        } finally {
            if (previous) active.set(tid, previous); else active.delete(tid);
        }
    };

    openOffline.implementation = function (activity, profile) {
        let fingerprint = null;
        try {
            if (profile !== null && profile.length > 61 && profile.length <= 2 * 1024 * 1024
                    && profile[6] === 6 && profile[7] === 1 && profile[8] === 1) {
                fingerprint = sha256(profile);
            }
        } catch (_) { status(); }
        // The official function verifies outer AES-GCM with Android Keystore.
        // Observe its v5 result rather than trying to export the hardware key.
        const output = openOffline.call(this, activity, profile);
        try {
            if (fingerprint !== null && !emitted.has(fingerprint) && output !== null
                    && output.length >= 157 && output.length === profile.length - 61
                    && output[0] === 70 && output[1] === 76 && output[2] === 88
                    && output[3] === 67 && output[4] === 70 && output[5] === 71
                    && output[6] === 5 && output[7] === 1) {
                console.log('FLEXNET_OFFLINE_CAPTURE ' + JSON.stringify({
                    schema: 'flexnet-v6-opened-inner/1',
                    fileSha256: fingerprint,
                    innerBase64: b64(output)
                }));
                emitted.add(fingerprint);
            }
        } catch (_) { status(); }
        return output;
    };
    console.log('FLEXNET_CAPTURE_STATUS ready; import your file normally');
});

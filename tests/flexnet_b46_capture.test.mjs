// Host mocks check observer flow only; these are not Android/Frida runtime tests.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../scripts/apk_analysis/flexnet_b46_capture.js', import.meta.url), 'utf8');
const vectors = JSON.parse(readFileSync(new URL('golden/flexnet_b46_vectors.json', import.meta.url), 'utf8'));
const capture = JSON.parse(readFileSync(new URL('golden/flexnet_b46_grant_capture.json', import.meta.url), 'utf8'));
const bytes = encoded => Array.from(Buffer.from(encoded, 'base64'));

function harness({ unwrapError = false, transportError = false, wrongWrapped = false, offlineError = false } = {}) {
    const logs = [], invocations = [], finalInvocations = [], offlineInvocations = [];
    const profile = bytes(vectors.online), wrapped = Array(256).fill(42), challenge = bytes(capture.challengeBase64);
    const grant = bytes(capture.grantBase64), result = [9, 8, 7];
    const offlineProfile = bytes(vectors.v6), inner = bytes(vectors.offline);
    const cipher = { getAlgorithm: () => 'RSA/ECB/OAEPPadding' };
    const app = { getPackageName: () => 'com.flexnet.tunnel', getPackageManager: () => ({
        getPackageInfo: () => ({ versionCode: { value: 46 } })
    }) };
    const doFinal = { call(receiver, input) {
        finalInvocations.push({ receiver, input });
        if (unwrapError) throw new Error('original unwrap failure');
        return grant;
    } };
    const transport = { call(receiver, ...args) {
        invocations.push({ receiver, args });
        doFinal.implementation.call(cipher, wrongWrapped ? [0] : wrapped);
        grant.fill(0); // Native cleanup must not erase the captured copy.
        if (transportError) throw new Error('original transport failure');
        return result;
    } };
    const openOffline = { call(receiver, ...args) {
        offlineInvocations.push({ receiver, args });
        if (offlineError) throw new Error('original offline failure');
        return inner;
    } };
    const classes = {
        'android.app.ActivityThread': { currentApplication: () => app },
        'android.util.Base64': { encodeToString: value => Buffer.from(value).toString('base64') },
        'java.security.MessageDigest': { getInstance: () => ({ digest: value => Array.from(createHash('sha256').update(Buffer.from(value)).digest()) }) },
        'com.betlog.ultrasshservice.config.VpnRouteBridge': { transport: { overload: (...args) => {
            assert.deepEqual(args, ['[B', '[B', '[B', '[B', 'java.lang.String', 'int', 'boolean']);
            return transport;
        } } },
        'com.betlog.ultrasshservice.config.d': { w: { overload: (...args) => {
            assert.deepEqual(args, ['com.betlog.baho.activities.BaseActivity', '[B']);
            return openOffline;
        } } },
        'javax.crypto.Cipher': { doFinal: { overload: value => {
            assert.equal(value, '[B'); return doFinal;
        } } }
    };
    vm.runInNewContext(source, {
        Java: { perform: fn => fn(), use: name => { assert.ok(classes[name], name); return classes[name]; } },
        Process: { getCurrentThreadId: () => 7 }, console: { log: value => logs.push(value) }
    });
    const receiver = {};
    const args = [profile, wrapped, challenge, null, 'flexnet.v5.route', 46, false];
    return { logs, invocations, finalInvocations, offlineInvocations, receiver, args, result, cipher, wrapped, grant,
        offlineProfile, inner, app,
        invoke: () => transport.implementation.call(receiver, ...args),
        invokeOffline: () => openOffline.implementation.call(receiver, app, offlineProfile),
        final: () => doFinal.implementation.call(cipher, wrapped) };
}

test('observer preserves original arguments/results and copies grant before native erasure', () => {
    const h = harness();
    assert.equal(h.invoke(), h.result);
    assert.equal(h.invocations.length, 1);
    assert.equal(h.invocations[0].receiver, h.receiver);
    assert.deepEqual(h.invocations[0].args, h.args);
    assert.equal(h.finalInvocations[0].receiver, h.cipher);
    assert.equal(h.finalInvocations[0].input, h.wrapped);
    const records = h.logs.filter(line => line.startsWith('FLEXNET_GRANT_CAPTURE '));
    assert.equal(records.length, 1);
    assert.deepEqual(JSON.parse(records[0].slice('FLEXNET_GRANT_CAPTURE '.length)), capture);
    h.final();
    assert.equal(h.logs.filter(line => line.startsWith('FLEXNET_GRANT_CAPTURE ')).length, 1);
});

test('original unwrap and transport exceptions propagate without emitting a capture', () => {
    for (const options of [{ unwrapError: true }, { transportError: true }]) {
        const h = harness(options);
        assert.throws(h.invoke, /original (unwrap|transport) failure/);
        assert.equal(h.invocations.length, 1);
        assert.equal(h.logs.some(line => line.startsWith('FLEXNET_GRANT_CAPTURE ')), false);
    }
});

test('unrelated unwraps and export operations do not emit import grants', () => {
    const unrelated = harness({ wrongWrapped: true });
    assert.equal(unrelated.invoke(), unrelated.result);
    const exporting = harness();
    exporting.args[6] = true;
    assert.equal(exporting.invoke(), exporting.result);
    for (const h of [unrelated, exporting]) {
        assert.equal(h.logs.some(line => line.startsWith('FLEXNET_GRANT_CAPTURE ')), false);
    }
});

test('offline observer preserves original call and copies the opened v5 container without reading a key', () => {
    const h = harness();
    assert.equal(h.invokeOffline(), h.inner);
    assert.equal(h.offlineInvocations.length, 1);
    assert.equal(h.offlineInvocations[0].receiver, h.receiver);
    assert.deepEqual(h.offlineInvocations[0].args, [h.app, h.offlineProfile]);
    const record = h.logs.find(line => line.startsWith('FLEXNET_OFFLINE_CAPTURE '));
    const opened = JSON.parse(record.slice('FLEXNET_OFFLINE_CAPTURE '.length));
    assert.deepEqual(opened, {
        schema: 'flexnet-v6-opened-inner/1',
        fileSha256: createHash('sha256').update(Buffer.from(h.offlineProfile)).digest('hex'),
        innerBase64: vectors.offline
    });
    h.inner.fill(0);
    assert.equal(opened.innerBase64, vectors.offline);
});

test('offline authentication exceptions propagate and an invalid inner container is not emitted', () => {
    const failed = harness({ offlineError: true });
    assert.throws(failed.invokeOffline, /original offline failure/);
    const invalid = harness();
    invalid.inner[6] = 6;
    assert.equal(invalid.invokeOffline(), invalid.inner);
    for (const h of [failed, invalid]) {
        assert.equal(h.logs.some(line => line.startsWith('FLEXNET_OFFLINE_CAPTURE ')), false);
    }
});

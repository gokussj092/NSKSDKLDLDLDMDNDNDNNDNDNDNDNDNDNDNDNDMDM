"""HC899 lossless open-layout conversion after authenticated user credentials."""
import copy
import os
import struct
from Crypto.Cipher import ChaCha20_Poly1305
from decoders.Python.apps.HTTP_Custom import codec
from decoders.Python import _hc_hccfg as hc
from .lossless import parse, equal, replace_values, put_member
from .notes import replace_note


def seal(key, aad, plain):
    nonce = os.urandom(24)
    c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    c.update(aad)
    encrypted, tag = c.encrypt_and_digest(plain)
    return nonce.hex(), (encrypted + tag).hex()


def unpack(section, key, aad):
    raw = hc._dec_section(section, key, aad)
    wrapped = raw.startswith(b'HPR1')
    if wrapped:
        # Unlike the legacy presentation reader, never accept unauthenticated
        # stream fallback when generating a configuration for another app.
        raw = hc._xdec(key, raw[4:28], aad+b'\0'+section['a'].encode()+b':r', raw[28:])
    if wrapped and not raw.startswith(b'HPC1'):
        raise ValueError('UNSUPPORTED_PROFILE_GRAMMAR')
    if raw.startswith(b'HPC1'): codec.parse_profile(raw, section['a'])
    return raw, hc._dec_sidecar(section, key, aad)


def migrate_payload(raw, sidecar):
    if sidecar is None:
        return raw
    r = hc._R(raw)
    if r.take(4) != b'HPC1' or r.u32() != 11:
        raise ValueError('UNSUPPORTED_PROFILE_GRAMMAR')
    for _ in range(3): r.txt()
    r.u32()
    for _ in range(3): r.txt()
    start = r.o
    options_raw = r.txt().encode('utf-8')
    end = r.o
    options = parse(options_raw)
    payload = sidecar.decode('utf-8')
    if type(options.get('customPayload')) is not str or options['customPayload'] not in ('', payload):
        raise ValueError('PAYLOAD_NOT_LOSSLESSLY_REPRESENTABLE')
    changed = replace_values(options_raw, {('customPayload',): payload})
    return raw[:start]+struct.pack('>I', len(changed))+changed+raw[end:]


def connection_view(decoded):
    value = copy.deepcopy(decoded['config'])
    for p in value:
        options = p.get('options')
        if not isinstance(options, dict) or 'custom_payload_sidecar_hex' in p:
            raise ValueError('UNSUPPORTED_PROFILE_OPTIONS')
        sidecar = p.pop('custom_payload_sidecar', None)
        if sidecar is not None:
            if options.get('customPayload', '') not in ('', sidecar):
                raise ValueError('CONFLICTING_PAYLOAD')
            options['customPayload'] = sidecar
        p.pop('options_text', None)
    return value


def export(raw, credentials, language='es'):
    password, hwid = credentials.get('password'), credentials.get('hwid')
    before = codec.decrypt(raw, password=password, hwid=hwid)
    env = codec.open_envelope(raw)
    if (type(env.get('n')) is not int or env['n'] != 899 or env.get('b') != 10 or
            env.get('e') not in ('n11', 'n12') or (env.get('c'), env.get('d')) != ('s1', 'h1')):
        raise ValueError('UNSUPPORTED_HC_VARIANT')
    key, aad = codec.derive(env, password, hwid)
    main_raw = hc._dec_section(env['i'], key, aad)
    main = parse(main_raw)
    if not equal(main.get('c'), env['f']) or main.get('g', {}).get('a') not in ('none', 'lock_all'):
        raise ValueError('UNSUPPORTED_ACCESS_LAYOUT')
    target = copy.deepcopy(env)
    features = list(env['f'])
    if 'profiles' not in features: features.append('profiles')
    target.update(e='n11', h=False if type(env.get('h')) is bool else 0,
                  f=features, g=os.urandom(32).hex())
    # These are the observed password KDF descriptor and HWID slot collection.
    # Their removal is intentional; all unrelated envelope metadata remains.
    for name in ('k', 'l', 'm', 'o'): target.pop(name, None)
    new_key, new_aad = codec.derive(target, None, None)
    edits = {('c',): features, ('g', 'a'): 'none'}
    for name in ('f', 'h', 'j'):
        if name in main['g']:
            if type(main['g'][name]) is not bool: raise ValueError('UNKNOWN_HWID_FLAG_TYPE')
            edits[('g', name)] = False
    if 'g' in main['g']:
        if type(main['g']['g']) is not list: raise ValueError('UNKNOWN_HWID_LIST_TYPE')
        edits[('g', 'g')] = []
    main_out = replace_note(replace_values(main_raw, edits), language)
    target['i']['b'], target['i']['c'] = seal(new_key, new_aad+b'\0'+env['i']['a'].encode(), main_out)
    for original, result in zip(hc._sec_list(env['j']), hc._sec_list(target['j'])):
        profile, sidecar = unpack(original, key, aad)
        if profile.startswith(b'HPC1'):
            if sidecar is not None and set(original['d']) != {'a', 'b'}:
                raise ValueError('UNKNOWN_SIDECAR_METADATA')
            profile = migrate_payload(profile, sidecar)
            result.pop('d', None)
        elif sidecar is not None:
            result['d']['a'], result['d']['b'] = seal(new_key, new_aad+b'\0'+original['a'].encode()+b':x', sidecar)
        result['b'], result['c'] = seal(new_key, new_aad+b'\0'+original['a'].encode(), profile)
    # Preserve the exact JSON tokens of unrelated envelope members. Removal of
    # known protection descriptors uses the same token-preserving helper.
    from .lossless import remove_member
    depth = None
    for n, logical in enumerate(hc._carriers(raw)):
        try: outer_raw = hc._xdec(codec.OUTER_KEY, logical[:24], codec.OUTER_AAD, logical[24:])
        except hc.HCError: continue
        depth = n; break
    if depth is None: raise ValueError('OUTER_AUTH_FAILED')
    outer_edits = {(k,): target[k] for k in ('e', 'h', 'f', 'g') if k in env}
    outer_edits.update({('i', k): target['i'][k] for k in ('b', 'c')})
    members = enumerate(env['j']) if isinstance(env['j'], list) else env['j'].items()
    removed = []
    for member, section in members:
        for k in ('b', 'c'): outer_edits[('j', member, k)] = target['j'][member][k]
        if 'd' in section and 'd' not in target['j'][member]: removed.append(('j', member))
        elif 'd' in section:
            for k in ('a', 'b'): outer_edits[('j', member, 'd', k)] = target['j'][member]['d'][k]
    outer_raw = replace_values(outer_raw, outer_edits)
    for parent in removed: outer_raw = remove_member(outer_raw, parent, 'd')
    for name in ('k', 'l', 'm', 'o'): outer_raw = remove_member(outer_raw, (), name)
    nonce, cipher = seal(codec.OUTER_KEY, codec.OUTER_AAD, outer_raw)
    output = bytes.fromhex(nonce+cipher)
    for _ in range(depth): output = output.decode('latin-1').encode('utf-8')
    after = codec.decrypt(output)  # No input password or HWID is supplied.
    if not equal(connection_view(before), connection_view(after)):
        raise ValueError('CONNECTION_MISMATCH')
    final = codec.open_envelope(output)
    if final['e'] != 'n11' or hc._h_flag(final) or 'o' in final or after['main']['g']['a'] != 'none':
        raise ValueError('OUTPUT_STILL_REQUIRES_CREDENTIALS')
    if not equal(parse(hc._dec_section(final['i'], new_key, new_aad)), parse(main_out)):
        raise ValueError('MAIN_MISMATCH')
    for previous, section in zip(hc._sec_list(env['j']), hc._sec_list(final['j'])):
        original_plain, _ = unpack(previous, key, aad)
        final_plain = hc._dec_section(section, new_key, new_aad)
        if original_plain.startswith(b'HPC1'):
            if not final_plain.startswith(b'HPC1'): raise ValueError('WRAPPED_PROFILE_REMAINS')
        elif original_plain != final_plain:
            raise ValueError('UNKNOWN_SECTION_CHANGED')
    return output

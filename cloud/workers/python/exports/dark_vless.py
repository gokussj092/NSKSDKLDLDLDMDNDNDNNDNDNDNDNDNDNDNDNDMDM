"""Audited VLESS/Xray template from Dark Tunnel build 32, not a generic converter.

JADX C5102.mo11267 and AbstractC0905.m5383..m5393. Reject any extra Xray
behavior that the editable Kotlin VLESS model cannot represent without loss.
"""
import json

from .lossless import parse, equal

MARKERS = ('$MUX_ENABLED', '$SOCKS5_LISTEN_PORT', '$HTTP_LISTEN_PORT')
DEFAULTS = {'host': 'localhost', 'port': 80, 'uuid': '', 'transportNetwork': 'Websocket',
            'tls': True, 'serverNameIndication': '', 'mux': False, 'wsPath': '',
            'wsHeaderHost': '', 'grpcServiceName': ''}


def generated_graph(config):
    c = dict(DEFAULTS, **config)
    stream = {'network': {'Tcp': 'tcp', 'Websocket': 'ws', 'Grpc': 'grpc'}[c['transportNetwork']],
              'security': 'tls' if c['tls'] else 'none',
              'tlsSettings': {'allowInsecure': True, 'serverName': c['serverNameIndication']}}
    if c['transportNetwork'] == 'Tcp':
        stream['tcpSettings'] = {}
    elif c['transportNetwork'] == 'Websocket':
        stream['wsSettings'] = {'headers': {'Host': c['wsHeaderHost']}, 'path': c['wsPath']}
    else:
        stream['grpcSettings'] = {'serviceName': c['grpcServiceName']}
    return {
        'inbounds': [
            {'listen': '$SOCKS5_LISTEN_HOST', 'port': '$SOCKS5_LISTEN_PORT', 'protocol': 'socks',
             'settings': {'auth': 'noauth', 'udp': True, 'userLevel': 8}},
            {'listen': '$HTTP_LISTEN_HOST', 'port': '$HTTP_LISTEN_PORT', 'protocol': 'http',
             'settings': {'userLevel': 8}}],
        'log': {'loglevel': 'none'},
        'outbounds': [{'mux': {'concurrency': 8, 'enabled': '$MUX_ENABLED'}, 'protocol': 'vless',
                      'settings': {'vnext': [{'address': c['host'], 'port': c['port'], 'users': [
                          {'encryption': 'none', 'id': c['uuid'], 'flow': '', 'level': 8,
                           'security': 'chacha20-poly1305'}]}]}, 'streamSettings': stream}],
        'policy': {'levels': {'8': {'connIdle': 300, 'downlinkOnly': 1, 'handshake': 4, 'uplinkOnly': 1}},
                   'system': {'statsOutboundUplink': False, 'statsOutboundDownlink': False}},
        'stats': {},
    }


def render(config):
    text = json.dumps(generated_graph(config), ensure_ascii=False, separators=(',', ':'))
    for marker in MARKERS:
        if text.count(json.dumps(marker)) != 1:
            raise ValueError('Ambiguous template marker')
        text = text.replace(json.dumps(marker), marker)
    return text


def parse_template(text):
    # Only quote the three *bare* tokens emitted by the original Kotlin builder.
    # Strings such as a password/UUID containing '$' are never normalized.
    if not isinstance(text, str) or len(text) > 4 * 1024 * 1024:
        raise ValueError('Invalid template size')
    output, pos, seen = [], 0, []
    decoder = json.JSONDecoder()
    while pos < len(text):
        if text[pos] == '"':
            _, end = decoder.raw_decode(text, pos)
            output.append(text[pos:end]); pos = end
        elif text[pos] == '$':
            marker = next((m for m in MARKERS if text.startswith(m, pos)), None)
            if marker is None:
                raise ValueError('Unsupported bare template marker')
            seen.append(marker); output.append(json.dumps(marker)); pos += len(marker)
        else:
            output.append(text[pos]); pos += 1
    if sorted(seen) != sorted(MARKERS):
        raise ValueError('Unexpected template marker count')
    return parse(''.join(output).encode('utf-8'))


def recover(text):
    graph = parse_template(text)
    try:
        outbound = graph['outbounds'][0]
        target = outbound['settings']['vnext'][0]
        stream = outbound['streamSettings']
        c = {'host': target['address'], 'port': target['port'], 'uuid': target['users'][0]['id'],
             'transportNetwork': {'tcp': 'Tcp', 'ws': 'Websocket', 'grpc': 'Grpc'}[stream['network']],
             'tls': stream['security'] == 'tls', 'serverNameIndication': stream['tlsSettings']['serverName']}
        if c['transportNetwork'] == 'Websocket':
            c.update(wsPath=stream['wsSettings']['path'], wsHeaderHost=stream['wsSettings']['headers']['Host'])
        if c['transportNetwork'] == 'Grpc':
            c['grpcServiceName'] = stream['grpcSettings']['serviceName']
        if (any(type(v) is not str for k, v in c.items() if k not in ('port', 'tls')) or
                type(c['port']) is not int or not 1 <= c['port'] <= 65535 or
                stream['security'] not in ('tls', 'none')):
            raise ValueError('Invalid VLESS field types')
        if not equal(graph, generated_graph(c)):
            raise ValueError('Xray behavior cannot be represented by the editable model')
        return c
    except (TypeError, KeyError, IndexError):
        raise ValueError('Unsupported Xray graph') from None

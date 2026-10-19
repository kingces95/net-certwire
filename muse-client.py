#!/usr/bin/env python3
"""Hal's muse-side certwire client for the myslackproxy test.
  register  hand the proxy my Slack identity cert (possession proven)
  listen    open the certwire connection, whitelist myslackproxy.net,
            print every delivered payload"""
import asyncio, base64, json, os, sys, urllib.request

sys.path.insert(0, '/home/hatch/workspace/certmint/work-2026-10-19-fqdn-flow')
from certwire_client import CertwireClient
from cryptography.hazmat.primitives import serialization

CERT_FILE = '/home/hatch/.certmint/cert.txt'
KEY_FILE = '/home/hatch/.certmint/id_ed25519.pem'
PROXY = 'https://myslackproxy.net'
UA = 'hal-muse-client.py/1.0 (myslackproxy test)'

cert_text = open(CERT_FILE).read()
key = serialization.load_pem_private_key(open(KEY_FILE, 'rb').read(), password=None)
sign = lambda data: base64.b64encode(key.sign(data)).decode()


def http(path, body=None):
    req = urllib.request.Request(PROXY + path, method='POST' if body else 'GET',
        data=json.dumps(body).encode() if body is not None else None,
        headers={'Content-Type': 'application/json', 'User-Agent': UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')


PROVISOR_CERT = os.environ.get(
    'PROVISOR_CERT',
    '/home/hatch/workspace/certmint/work-2026-10-19-fqdn-flow/cert-serial-22-myslackproxy.net.txt')
PROVISOR_DOMAIN = 'myslackproxy.net'


def cert_fields(text):
    fields, identities = {}, []
    for ln in text.strip().split('\n'):
        if ': ' in ln:
            k, v = ln.split(': ', 1)
            (identities.append(v) if k == 'identity' else fields.__setitem__(k, v))
    return fields, identities


def slack_team(text):
    for ident in cert_fields(text)[1]:
        kv = dict(t.split('=', 1) for t in ident.split() if '=' in t)
        if kv.get('provider') == 'slack':
            return kv.get('team')
    return None


def raw_priv(k):
    from cryptography.hazmat.primitives import serialization
    return k.private_bytes(serialization.Encoding.Raw,
                           serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())


def transport_ctx(cert_file=CERT_FILE):
    import certwire_crypto as cc
    text = open(cert_file).read()
    fields, _ = cert_fields(text)
    return cc.context_string(f"{fields['issuer']}/{fields['serial']}",
                             PROVISOR_DOMAIN, slack_team(text))


def register(cert_file=CERT_FILE, transport_key=None):
    text = open(cert_file).read()
    serial = [ln.split(': ', 1)[1] for ln in text.split('\n') if ln.startswith('serial: ')][0]
    code, ch = http('/v1/routes/challenge')
    assert code == 200, (code, ch)
    sig = sign(f"myslackproxy-route-v1\n{serial}\n{ch['nonce']}".encode())
    body = {'cert': text, 'nonce': ch['nonce'], 'signature': sig}
    if transport_key is not None:
        import certwire_crypto as cc
        prov = open(PROVISOR_CERT).read()
        key_line = [ln for ln in prov.split('\n') if ln.startswith('key: ')][0]
        body['transport_key_sealed'] = cc.seal_transport_key(
            transport_key, transport_ctx(cert_file), raw_priv(key),
            cc.openssh_raw(key_line.split(': ', 1)[1]))
    code, r = http('/v1/routes', body)
    print('register:', code, r)
    return r


async def listen(cert_file=CERT_FILE):
    text = open(cert_file).read()

    async def on_deliver(frm, payload):
        print(f'DELIVERED from {frm}: {json.dumps(payload)[:400]}', flush=True)

    c = CertwireClient(os.environ.get('CERTWIRE_URL', 'wss://certwire.net'), text, sign,
                       on_deliver=on_deliver, log=lambda m: print(m, flush=True))
    task = asyncio.ensure_future(c.run())
    for _ in range(100):
        if c.address:
            break
        await asyncio.sleep(0.2)
    await c.whitelist(['myslackproxy.net'])
    print(f'LISTENING as {c.address}, whitelist myslackproxy.net', flush=True)
    await task


async def serve(cert_file=CERT_FILE):
    """The encrypted reference flow: register with a freshly minted
    transport key (sealed to the provisor), then listen and decrypt.
    Keys live only in this process. A payload that does not decrypt
    is dropped and triggers a debounced re-registration with a new
    key — the single recovery verb for every key failure."""
    import secrets as _secrets, time as _time
    import certwire_crypto as cc
    text = open(cert_file).read()
    ctx = transport_ctx(cert_file)
    state = {'key': _secrets.token_bytes(32), 'last_rereg': 0.0}
    register(cert_file, transport_key=state['key'])

    async def on_deliver(frm, payload):
        if isinstance(payload, dict) and payload.get('enc') == 'v1':
            print(f'ENVELOPE from {frm}: {json.dumps(payload)[:160]}…', flush=True)
            try:
                dir_key = cc.direction_key(state['key'], 'provisor-to-muse', ctx)
                plain = cc.decrypt_payload(dir_key, payload,
                                           cc.aad_string(frm, c.address))
                print(f'DELIVERED (decrypted) from {frm}: {plain.decode()[:400]}',
                      flush=True)
                return
            except Exception:
                print('UNDECRYPTABLE payload dropped', flush=True)
                if _time.time() - state['last_rereg'] >= 180:
                    state['last_rereg'] = _time.time()
                    state['key'] = _secrets.token_bytes(32)
                    print('re-registering with a fresh transport key', flush=True)
                    register(cert_file, transport_key=state['key'])
                return
        print(f'DELIVERED (unencrypted) from {frm}: {json.dumps(payload)[:400]}',
              flush=True)

    c = CertwireClient(os.environ.get('CERTWIRE_URL', 'wss://certwire.net'), text, sign,
                       on_deliver=on_deliver, log=lambda m: print(m, flush=True))
    task = asyncio.ensure_future(c.run())
    for _ in range(100):
        if c.address:
            break
        await asyncio.sleep(0.2)
    await c.whitelist(['myslackproxy.net'])
    print(f'SERVING as {c.address}, encrypted, whitelist myslackproxy.net', flush=True)
    await task


if __name__ == '__main__':
    if sys.argv[1] == 'register':
        register(sys.argv[2] if len(sys.argv) > 2 else CERT_FILE)
    elif sys.argv[1] == 'serve':
        asyncio.run(serve(sys.argv[2] if len(sys.argv) > 2 else CERT_FILE))
    else:
        asyncio.run(listen(sys.argv[2] if len(sys.argv) > 2 else CERT_FILE))

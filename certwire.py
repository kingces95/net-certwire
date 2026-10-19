#!/usr/bin/env python3
"""certwire — the authenticated message router (first build, 2026-10-19).

Connections are authenticated ONCE at open: the client presents a
certmint cert and proves possession of its key over a server nonce.
The connection then binds the cert's address (issuer/serial) and every
payload it carries is routed on that binding — no per-message cert
verification. A payload is forwarded only when the destination's
whitelist admits the sender (matched by the sender cert's domain,
its address, or its key fingerprint). Routing is UDP-like: a payload
either dispatches to a currently bound destination or is dropped on
the spot — certwire keeps no queue and offers no delivery guarantee.
A binding dies with its connection or at the cert's expiry, whichever
is first.
"""
import asyncio, base64, json, os, secrets, struct, time, urllib.request

import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MINT_BASE = 'https://certmint.net'
UA = 'certwire/1.0'
HOST = os.environ.get('CERTWIRE_HOST', '127.0.0.1')
PORT = int(os.environ.get('CERTWIRE_PORT', '18081'))
_mint = {'key_raw': None, 'revoked': set(), 'fetched': 0}


def mint_pubkey_raw():
    if time.time() - _mint['fetched'] < 300:
        return _mint['key_raw']
    req = urllib.request.Request(MINT_BASE + '/pubkey', headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        info = json.loads(r.read())
    blob = base64.b64decode(info['key'].split()[1])
    ln, = struct.unpack('>I', blob[:4]); off = 4 + ln
    ln2, = struct.unpack('>I', blob[off:off + 4])
    _mint['key_raw'] = blob[off + 4:off + 4 + ln2]
    req = urllib.request.Request(MINT_BASE + '/revoked', headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        _mint['revoked'] = set(r.read().decode().split())
    _mint['fetched'] = time.time()
    return _mint['key_raw']


def parse_cert(text):
    lines = text.strip().split('\n')
    if not lines[-1].startswith('signature: '):
        raise ValueError('no signature line')
    body = ('\n'.join(lines[:-1]) + '\n').encode()
    fields, identities = {}, []
    for ln in lines[:-1]:
        if ': ' in ln:
            k, v = ln.split(': ', 1)
            (identities.append(v) if k == 'identity' else fields.__setitem__(k, v))
    return fields, identities, body, lines[-1].split(': ', 1)[1]


def parse_openssh(line):
    blob = base64.b64decode(line.strip().split()[1])
    ln, = struct.unpack('>I', blob[:4]); off = 4 + ln
    ln2, = struct.unpack('>I', blob[off:off + 4])
    return blob[off + 4:off + 4 + ln2]


def cert_expiry_epoch(fields):
    from datetime import datetime, timezone
    return datetime.strptime(fields['expires'], '%Y-%m-%dT%H:%M:%SZ').replace(
        tzinfo=timezone.utc).timestamp()


class Conn:
    def __init__(self, ws):
        self.ws = ws
        self.address = None
        self.fields = None
        self.whitelist = set()
        self.expires = 0


BINDINGS = {}   # address -> Conn


def sender_names(conn):
    f = conn.fields
    names = {conn.address, f.get('key-fingerprint', '')}
    if f.get('domain'):
        names.add(f['domain'])
    return names


def admitted(dest, sender):
    return bool(dest.whitelist & sender_names(sender))


async def handle(ws):
    conn = Conn(ws)
    nonce = secrets.token_urlsafe(32)
    try:
        await ws.send(json.dumps({'op': 'challenge', 'nonce': nonce}))
        async for raw in ws:
            msg = json.loads(raw)
            op = msg.get('op')
            if op == 'open' and conn.address is None:
                try:
                    fields, identities, body, sig = parse_cert(msg.get('cert') or '')
                    Ed25519PublicKey.from_public_bytes(mint_pubkey_raw()).verify(
                        base64.b64decode(sig), body)
                    serial = fields['serial']
                    if serial in _mint['revoked']:
                        raise ValueError('cert revoked')
                    exp = cert_expiry_epoch(fields)
                    if exp < time.time():
                        raise ValueError('cert expired')
                    raw_key = parse_openssh(fields['key'])
                    Ed25519PublicKey.from_public_bytes(raw_key).verify(
                        base64.b64decode(msg.get('signature') or ''),
                        f"certwire-open-v1\n{serial}\n{nonce}".encode())
                except Exception as e:
                    await ws.send(json.dumps({'op': 'error', 'error': f'open refused: {e}'}))
                    return
                conn.fields = fields
                conn.address = f"{fields['issuer']}/{serial}"
                conn.expires = exp
                BINDINGS[conn.address] = conn
                print(f"bound {conn.address} domain={fields.get('domain', '')} "
                      f"expires={fields['expires']}", flush=True)
                await ws.send(json.dumps({'op': 'open_ok', 'address': conn.address}))
            elif op == 'whitelist' and conn.address:
                conn.whitelist = set(msg.get('names') or [])
                print(f'{conn.address} whitelist: {sorted(conn.whitelist)}', flush=True)
                await ws.send(json.dumps({'op': 'whitelist_ok'}))
            elif op == 'send' and conn.address:
                if conn.expires < time.time():
                    await ws.send(json.dumps({'op': 'error', 'error': 'cert expired; reopen'}))
                    return
                to = msg.get('to') or ''
                dest = BINDINGS.get(to)
                if dest is not None and dest.expires >= time.time():
                    if admitted(dest, conn):
                        await dest.ws.send(json.dumps({'op': 'deliver', 'from': conn.address,
                                                       'payload': msg.get('payload')}))
                        await ws.send(json.dumps({'op': 'sent', 'to': to}))
                    else:
                        await ws.send(json.dumps({'op': 'refused', 'to': to,
                                                  'error': 'not whitelisted by destination'}))
                else:
                    print(f'dropped {conn.address} -> {to}: destination not bound', flush=True)
                    await ws.send(json.dumps({'op': 'dropped', 'to': to,
                                              'error': 'destination not bound'}))
            else:
                await ws.send(json.dumps({'op': 'error', 'error': 'unknown or out-of-order op'}))
    except websockets.ConnectionClosed:
        pass
    finally:
        if conn.address and BINDINGS.get(conn.address) is conn:
            del BINDINGS[conn.address]
            print(f'unbound {conn.address}', flush=True)


async def reaper():
    while True:
        await asyncio.sleep(30)
        now = time.time()
        for addr in list(BINDINGS):
            c = BINDINGS[addr]
            if c.expires < now:
                print(f'expiring binding {addr}', flush=True)
                await c.ws.close()


async def main():
    mint_pubkey_raw()
    async with websockets.serve(handle, HOST, PORT):
        print(f'certwire listening on {HOST}:{PORT}', flush=True)
        asyncio.ensure_future(reaper())
        await asyncio.Future()


if __name__ == '__main__':
    asyncio.run(main())

#!/usr/bin/env python3
"""myslackproxy: the Slack Socket Mode listener + certwire bridge.

Holds the app-level-token connection to Slack (acking every envelope),
and forwards events to muses over certwire: for each event, the routes
registry (muses who handed the proxy a Slack identity cert, possession
proven) is consulted; an event whose (team, user) matches a route's
Slack identity is sent to that route's cert address. The bridge's own
certwire connection is opened with the provisor's domain cert; the
private key never leaves this host."""
import asyncio, base64, json, os, urllib.request

import websockets

TOKEN = os.environ['SLACK_APP_TOKEN']
UA = 'myslackproxy-listener/2.0'
CERTWIRE_URL = os.environ.get('CERTWIRE_URL', 'ws://127.0.0.1:18081')
ROUTES_PATH = '/etc/myslackproxy/routes.json'
DOMAIN_CERT = '/etc/myslackproxy/domain-cert.txt'
DOMAIN_KEY = '/etc/myslackproxy/provisor-ed25519'


def open_url():
    req = urllib.request.Request('https://slack.com/api/apps.connections.open',
                                 method='POST',
                                 headers={'Authorization': f'Bearer {TOKEN}',
                                          'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        resp = json.loads(r.read())
    if not resp.get('ok'):
        raise RuntimeError(f"connections.open refused: {resp.get('error')}")
    return resp['url']


def load_routes():
    try:
        with open(ROUTES_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def make_signer():
    from cryptography.hazmat.primitives import serialization
    with open(DOMAIN_KEY, 'rb') as f:
        key = serialization.load_ssh_private_key(f.read(), password=None)
    return lambda data: base64.b64encode(key.sign(data)).decode()


# ---------- certwire payload encryption (transport keys) ----------
# Keys arrive sealed to this host's domain key at muse registration
# time and are held by the web service in memory; the bridge takes
# each blob exactly once (take-once) and opens it here. Opened keys
# live ONLY in this process's memory (KEYS). Policy (Chris,
# 2026-10-19): a key dies with this process, and at the first
# dropped payload its copy is deleted and the certwire connection
# is closed; the muse re-registers to mint a fresh one.
import urllib.error
import certwire_crypto as cc

PROVISOR_DOMAIN = 'myslackproxy.net'
INTERNAL_BASE = 'http://127.0.0.1:18080'
INTERNAL_TOKEN_PATH = '/etc/myslackproxy/internal.token'
KEYS = {}  # route fingerprint -> {'epoch': int, 'dir_key': bytes}


def _provisor_priv_raw():
    from cryptography.hazmat.primitives import serialization
    with open(DOMAIN_KEY, 'rb') as f:
        key = serialization.load_ssh_private_key(f.read(), password=None)
    return key.private_bytes(serialization.Encoding.Raw,
                             serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())


def _internal(method, path):
    with open(INTERNAL_TOKEN_PATH) as f:
        token = f.read().strip()
    req = urllib.request.Request(INTERNAL_BASE + path, method=method,
                                 headers={'X-Internal-Token': token,
                                          'User-Agent': UA})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        return e.code, {}


def ensure_key(fp, route, team):
    """The direction key for a route, or None when no live key is
    held (event must then be dropped: re-registration is the only
    way back, by design)."""
    epoch = route.get('key_epoch')
    if not epoch:
        return None
    held = KEYS.get(fp)
    if held and held['epoch'] == epoch:
        return held['dir_key']
    KEYS.pop(fp, None)
    import urllib.parse
    code, resp = _internal('GET', '/internal/sealed-key?fingerprint='
                           + urllib.parse.quote(fp) + f'&epoch={epoch}')
    if code != 200:
        return None
    try:
        key_line = [ln for ln in route['cert'].split('\n')
                    if ln.startswith('key: ')][0].split(': ', 1)[1]
        ctx = cc.context_string(route['address'], PROVISOR_DOMAIN, team)
        raw = cc.open_transport_key(resp['sealed'], ctx, _provisor_priv_raw(),
                                    cc.openssh_raw(key_line))
        dir_key = cc.direction_key(raw, 'provisor-to-muse', ctx)
    except Exception as e:
        print(f'transport key open failed for {route["address"]}: '
              f'{type(e).__name__}', flush=True)
        return None
    KEYS[fp] = {'epoch': epoch, 'dir_key': dir_key}
    print(f'transport key opened for {route["address"]} (epoch {epoch})', flush=True)
    return dir_key


async def on_cw_dropped(to):
    """Router dropped a payload: delete that route's key and close
    the certwire connection (the lifecycle policy)."""
    for fp, route in load_routes().items():
        if route.get('address') == to:
            if KEYS.pop(fp, None) is not None:
                print(f'transport key deleted for {to} (payload dropped)', flush=True)
            break
    await CW.reconnect()


CW = None  # CertwireClient, set in main


async def forward(payload):
    p = payload
    ev = p.get('event', {})
    routes = load_routes()
    for fp, route in routes.items():
        for ident in route.get('identities', []):
            if ident.get('team') == p.get('team_id') and ident.get('sub') == ev.get('user'):
                out = {'kind': 'slack_event', 'team_id': p.get('team_id'),
                       'event_id': p.get('event_id'),
                       'event': {k: ev.get(k) for k in
                                 ('type', 'channel', 'user', 'text', 'ts') if k in ev}}
                dir_key = ensure_key(fp, route, ident.get('team'))
                if dir_key is None or CW.address is None:
                    print(f"event {p.get('event_id')} dropped: no live transport "
                          f"key for {route['address']} (awaiting re-registration)",
                          flush=True)
                    continue
                envelope = cc.encrypt_payload(
                    dir_key, json.dumps(out).encode(),
                    cc.aad_string(CW.address, route['address']))
                await CW.send(route['address'], envelope)
                print(f"forwarded event {p.get('event_id')} to {route['address']} "
                      f"(encrypted)", flush=True)


async def run_once():
    url = open_url()
    print('connecting…', flush=True)
    async with websockets.connect(url, ping_interval=30, ping_timeout=60) as ws:
        async for raw in ws:
            msg = json.loads(raw)
            env_id = msg.get('envelope_id')
            if env_id:
                await ws.send(json.dumps({'envelope_id': env_id}))
            kind = msg.get('type', '?')
            if kind == 'hello':
                ci = msg.get('connection_info', {})
                print(f"hello: app {ci.get('app_id')} connected, "
                      f"{msg.get('num_connections')} connection(s)", flush=True)
            elif kind == 'events_api':
                p = msg.get('payload', {})
                ev = p.get('event', {})
                print(f"event: team={p.get('team_id')} type={ev.get('type')} "
                      f"channel={ev.get('channel')} user={ev.get('user')}", flush=True)
                await forward(p)
            elif kind == 'disconnect':
                print(f"disconnect requested ({msg.get('reason')}); reconnecting", flush=True)
                return
            else:
                print(f'{kind}: {str(msg)[:200]}', flush=True)


async def slack_loop():
    while True:
        try:
            await run_once()
        except Exception as e:
            print(f'connection error: {type(e).__name__}: {e}', flush=True)
        await asyncio.sleep(5)


async def main():
    global CW
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from certwire_client import CertwireClient
    with open(DOMAIN_CERT) as f:
        cert_text = f.read()
    # Bridge (re)start invalidates sealed keys still held by the web
    # service: keys do not survive a recycle, by policy.
    for attempt in range(10):
        try:
            code, _ = _internal('POST', '/internal/purge')
            print(f'sealed-key purge at bridge start: HTTP {code}', flush=True)
            if code == 200:
                break
        except Exception as e:
            print(f'sealed-key purge attempt {attempt + 1} failed: '
                  f'{type(e).__name__}', flush=True)
        await asyncio.sleep(2)
    CW = CertwireClient(CERTWIRE_URL, cert_text, make_signer(),
                        log=lambda m: print(m, flush=True),
                        on_dropped=on_cw_dropped)
    await asyncio.gather(slack_loop(), CW.run())


if __name__ == '__main__':
    asyncio.run(main())

#!/usr/bin/env python3
"""myslackproxy: the Slack Socket Mode listener + certwire bridge.

Holds the app-level-token connection to Slack (acking every envelope),
and forwards events to muses over certwire: for each event, the routes
registry (muses who handed the proxy a Slack identity cert, possession
proven) is consulted; an event whose (team, user) matches a route's
Slack identity is sent to that route's cert address. The bridge's own
certwire connection is opened with the provisor's domain cert; the
private key never leaves this host."""
import asyncio, base64, json, os, urllib.parse, urllib.request

import websockets

TOKEN = os.environ['SLACK_APP_TOKEN']
UA = 'myslackproxy-listener/2.0'
CERTWIRE_URL = os.environ.get('CERTWIRE_URL', 'ws://127.0.0.1:18081')
ROUTES_PATH = '/etc/myslackproxy/routes.json'
DOMAIN_CERT = '/etc/myslackproxy/domain-cert.txt'
DOMAIN_KEY = '/etc/myslackproxy/provisor-ed25519'
# Bot-token store, written by myslackproxy-web.py at install time.
# The listener holds only the app-level token (SLACK_APP_TOKEN, for
# Socket Mode); reactions.add needs the bot token, which lives here
# Fernet-encrypted (key beside it, same paths the web service uses).
STORE_PATH = os.environ.get('MYSLACKPROXY_STORE',
                            '/etc/myslackproxy/installations.json')
STORE_KEY_PATH = os.environ.get('MYSLACKPROXY_KEY',
                                '/etc/myslackproxy/store-key')


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
from certwire_app import AppClient

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


# ---------- muse-requested reactions (app layer) ----------
# A registered muse may ask the proxy to fire a Slack reaction as
# the proxy bot: app post to /slack/react with body
# {"channel", "ts", "name"}. This exists because the per-muse bot
# apps are gone — the proxy's bot is the only bot identity left in
# the workspace. Admission is the app layer's (sender cert address,
# path) pair, with the sender set synced from routes.json: only a
# muse holding a registered route can ask, and the team is taken
# from that route's identities, never from the request body, so a
# muse can only react in a workspace it is registered for.
_BOT_TOKENS = {}   # team_id -> bot access token, memory only


def _bot_token(team_id):
    if team_id in _BOT_TOKENS:
        return _BOT_TOKENS[team_id]
    try:
        from cryptography.fernet import Fernet
        with open(STORE_KEY_PATH, 'rb') as f:
            fernet = Fernet(f.read().strip())
        with open(STORE_PATH) as f:
            store = json.load(f)
    except Exception as e:
        print(f'react: bot token store unreadable: {type(e).__name__}',
              flush=True)
        return None
    for rec in store.values():
        if rec.get('team_id') == team_id and rec.get('access_token_enc'):
            try:
                tok = fernet.decrypt(
                    rec['access_token_enc'].encode()).decode()
            except Exception:
                return None
            _BOT_TOKENS[team_id] = tok
            return tok
    return None


def _slack_reactions_add(token, channel, ts, name):
    data = urllib.parse.urlencode(
        {'channel': channel, 'timestamp': ts, 'name': name}).encode()
    req = urllib.request.Request(
        'https://slack.com/api/reactions.add', data=data, method='POST',
        headers={'Authorization': f'Bearer {token}',
                 'Content-Type': 'application/x-www-form-urlencoded',
                 'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


async def react_handler(frm, method, path, body):
    """POST /slack/react — ack status is the Slack verdict, mapped:
    200 ok or already_reacted (idempotent success, the relay's
    standing semantics), 400 malformed request or Slack refusal,
    403 Slack auth/scope failure, 500 no bot token on file,
    502 Slack unreachable. The v1 ack carries status only, so the
    Slack error string itself cannot ride back to the muse."""
    if method != 'POST':
        return 405
    try:
        req = json.loads(body or '{}')
        channel, ts, name = req['channel'], str(req['ts']), req['name']
    except Exception:
        return 400
    route = next((r for r in load_routes().values()
                  if r.get('address') == frm), None)
    token = None
    for ident in (route or {}).get('identities', []):
        token = _bot_token(ident.get('team'))
        if token:
            break
    if not token:
        print(f'react: no bot token for sender {frm}', flush=True)
        return 500
    try:
        resp = _slack_reactions_add(token, channel, ts, name)
    except Exception as e:
        print(f'react: slack call failed: {type(e).__name__}', flush=True)
        return 502
    if resp.get('ok') or resp.get('error') == 'already_reacted':
        print(f'react: {name} on {ts} in {channel} for {frm}', flush=True)
        return 200
    err = resp.get('error', 'unknown')
    print(f'react: slack refused for {frm}: {err}', flush=True)
    if err in ('invalid_auth', 'token_revoked', 'not_authed',
               'missing_scope'):
        _BOT_TOKENS.clear()   # force a re-read of the store next time
        return 403
    return 400


def _route_addresses():
    return sorted({r.get('address') for r in load_routes().values()
                   if r.get('address')})


def _sync_react_admission(app):
    """Keep the app layer's admission and the router whitelist in
    step with routes.json. Both must name the route addresses: the
    app rules admit /slack/react posts from them, and the certwire
    router only forwards a payload to this connection when the
    DESTINATION (us) whitelists the sender — an empty whitelist
    refuses everything, so without this the posts never arrive."""
    addrs = _route_addresses()
    app.rules = [(a, '/slack/react', react_handler) for a in addrs]
    if CW is not None and CW.whitelist_names != addrs:
        asyncio.ensure_future(CW.whitelist(addrs))


class _ReactApp(AppClient):
    """AppClient that re-syncs react admission from routes.json on
    every delivery (routes change as muses register; the bridge
    already re-reads the file per event). Non-app payloads keep the
    old behaviour: none are expected inbound, AppClient logs them.
    Ack frames for posts this bridge sends (it sends none today)
    resolve through AppClient unchanged, and AppClient chains the
    on_dropped hook installed before it wraps the client."""

    async def _on_deliver(self, frm, payload):
        _sync_react_admission(self)
        await super()._on_deliver(frm, payload)


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
    # App layer over the same connection: admits /slack/react posts
    # from registered route addresses (see _ReactApp). Wrapping
    # replaces CW.on_deliver and chains on_cw_dropped.
    app = _ReactApp(CW, log=lambda m: print(m, flush=True))
    _sync_react_admission(app)
    await asyncio.gather(slack_loop(), CW.run())


if __name__ == '__main__':
    asyncio.run(main())

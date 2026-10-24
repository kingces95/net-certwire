#!/usr/bin/env python3
"""muse-appd — a muse's certwire app-layer daemon.

One cert-bound connection to the certwire router carries every
inbound app for this muse. The daemon owns the endpoint's firewall
(the app layer's admission table) and demuxes certified paths to
handlers:

  knock   posts from the knockwire service's cert, path
          /<guid>/<service...>, are written as knock files into
          the local knock spool (~/.knockwire/queue/<service>/),
          byte-identical to what the SSH-tunnel demux writes, and
          acked — the knockwire mailbox retries against that ack.
  slack   legacy (pre-app-layer) encrypted envelopes from the
          Slack provisor's cert are decrypted under the transport
          key sealed at route registration and translated into the
          Slack relay's record shape. Delivery mode is config:
          "shadow" writes a parallel spool + log for parity
          comparison; "live" writes the relay's own queue.

Config is a JSON file (argv[1] or MUSE_APPD_CONFIG): cert/key
paths, router URL, whitelist names, knockwire + provisor cert
addresses, the guid, spool dirs, and the slack mode. No secrets in
config — keys are referenced by path only.
"""
import asyncio, json, os, secrets, sys, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import certwire_crypto as cc
from certwire_client import CertwireClient
from certwire_app import AppClient
from cryptography.hazmat.primitives import serialization

CFG = json.load(open(sys.argv[1] if len(sys.argv) > 1 else
                     os.environ.get('MUSE_APPD_CONFIG',
                                    'muse-appd.json')))


def log(msg):
    ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    print(f'{ts} appd: {msg}', flush=True)


def cert_fields(text):
    fields, identities = {}, []
    for ln in text.strip().split('\n'):
        if ': ' in ln:
            k, v = ln.split(': ', 1)
            (identities.append(v) if k == 'identity'
             else fields.__setitem__(k, v))
    return fields, identities


CERT_TEXT = open(CFG['cert_file']).read()
FIELDS, IDENTITIES = cert_fields(CERT_TEXT)
MY_ADDRESS = f"{FIELDS['issuer']}/{FIELDS['serial']}"
_key = serialization.load_pem_private_key(
    open(CFG['key_file'], 'rb').read(), password=None)
sign = lambda data: __import__('base64').b64encode(_key.sign(data)).decode()


def raw_priv(k):
    return k.private_bytes(serialization.Encoding.Raw,
                           serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())


def slack_team():
    for ident in IDENTITIES:
        kv = dict(t.split('=', 1) for t in ident.split() if '=' in t)
        if kv.get('provider') == 'slack':
            return kv.get('team')
    return None


TRANSPORT_CTX = cc.context_string(MY_ADDRESS, CFG['provisor_domain'],
                                  slack_team())

# ---------- Slack provisor route registration ----------

def http_json(url, body=None):
    req = urllib.request.Request(
        url, method='POST' if body is not None else 'GET',
        data=json.dumps(body).encode() if body is not None else None,
        headers={'Content-Type': 'application/json',
                 'User-Agent': 'muse-appd/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')


STATE = {'key': None, 'last_rereg': 0.0, 'registered': False}


def _route_confirmed(t0):
    """The proxied door sometimes drops the POST response after
    processing it. Registration is confirmed by reading the public
    route list back: my fingerprint with an updated_at at or after
    this attempt means the sealed key on file is the one just sent,
    whatever the POST claimed."""
    try:
        code, r = http_json(CFG['provisor_url'] + '/v1/routes')
        if code != 200:
            return False
        for route in r.get('routes', []):
            if route.get('fingerprint') != FIELDS['key-fingerprint']:
                continue
            upd = route.get('updated_at') or ''
            epoch = time.mktime(time.strptime(upd, '%Y-%m-%dT%H:%M:%SZ')) \
                - time.timezone
            return epoch >= t0 - 10
    except Exception:
        return False
    return False


def register_route():
    """(Re)register this muse's Slack route with a fresh transport
    key sealed to the provisor. Re-registration is the single
    recovery verb for every key failure (see certwire_crypto)."""
    base = CFG['provisor_url']
    try:
        code, ch = http_json(base + '/v1/routes/challenge')
    except Exception as e:
        raise RuntimeError(f'challenge request lost: {e}')
    assert code == 200, (code, ch)
    # Rotate the key only once the challenge is in hand: a failed
    # challenge must not orphan the key a previous landed POST
    # sealed for us (the retry loop checks for that landing first).
    STATE['key'] = secrets.token_bytes(32)
    sig = sign(f"myslackproxy-route-v1\n{FIELDS['serial']}\n{ch['nonce']}".encode())
    prov = open(CFG['provisor_cert_file']).read()
    key_line = [ln for ln in prov.split('\n')
                if ln.startswith('key: ')][0]
    body = {'cert': CERT_TEXT, 'nonce': ch['nonce'], 'signature': sig,
            'transport_key_sealed': cc.seal_transport_key(
                STATE['key'], TRANSPORT_CTX, raw_priv(_key),
                cc.openssh_raw(key_line.split(': ', 1)[1]))}
    t0 = time.time()
    try:
        code, r = http_json(base + '/v1/routes', body)
        log(f'slack route register: {code} {r}')
        ok = code in (200, 201)
    except Exception as e:
        log(f'slack route register: response lost ({e}); confirming')
        ok = False
    if not ok:
        ok = _route_confirmed(t0)
        if ok:
            log('slack route register: confirmed via route list')
    if ok:
        STATE['registered'] = True
    STATE['last_rereg'] = time.time()


# ---------- handlers ----------

def knock_handler(frm, method, path, body):
    """A knockwire knock: /<guid>/<service...> -> one spool file,
    exactly as the tunnel demux writes it (name + content), so the
    channel hooks consume both transports identically."""
    guid = CFG['guid']
    rest = path[len(guid) + 1:]
    if not rest.startswith('/'):
        return 400
    seg = rest.strip('/').split('/')[0].lower()
    service = ''.join(c for c in seg if c.isalnum() or c == '-') or 'misc'
    qdir = os.path.join(os.path.expanduser(CFG['knock_queue_dir']), service)
    os.makedirs(qdir, mode=0o700, exist_ok=True)
    name = f'{time.time():.3f}-{os.getpid()}.knock'
    with open(os.path.join(qdir, name), 'w') as f:
        f.write(f'{method} {rest}\n')
    log(f'knock via certwire: {method} {rest} -> spool/{service}')
    return 200


def _append(path, obj):
    with open(path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(obj, ensure_ascii=False) + '\n')


async def slack_handler(frm, payload):
    """Legacy encrypted envelope from the provisor bridge."""
    if not (isinstance(payload, dict) and payload.get('enc') == 'v1'):
        log(f'slack: non-envelope payload from {frm}, dropped')
        return
    try:
        dir_key = cc.direction_key(STATE['key'], 'provisor-to-muse',
                                   TRANSPORT_CTX)
        plain = cc.decrypt_payload(dir_key, payload,
                                   cc.aad_string(frm, CW.address))
        msg = json.loads(plain.decode())
    except Exception:
        log('slack: UNDECRYPTABLE payload dropped')
        if time.time() - STATE['last_rereg'] >= 180:
            log('slack: re-registering with a fresh transport key')
            try:
                register_route()
            except Exception as e:
                log(f'slack: re-register failed: {e}')
        return
    if msg.get('kind') != 'slack_event':
        log(f'slack: unexpected kind {msg.get("kind")!r}, dropped')
        return
    ev = msg.get('event') or {}
    channel = ev.get('channel') or ''
    rec = {'ts': ev.get('ts') or '', 'event_id': msg.get('event_id'),
           'channel': channel,
           'channel_type': 'im' if channel.startswith('D') else 'channel',
           'user': ev.get('user') or '', 'bot': False,
           'text': ev.get('text') or '', 'thread_ts': '',
           'at': int(time.time())}
    relay = os.path.expanduser(CFG['slack_relay_dir'])
    if CFG.get('slack_mode') == 'live':
        _append(os.path.join(relay, 'channel.jsonl'), rec)
        _append(os.path.join(relay, 'queue.jsonl'), rec)
        qd = os.path.join(relay, 'queue.d')
        os.makedirs(qd, exist_ok=True)
        name = f"{rec['ts']}-{rec['event_id']}.knock"
        tmp = os.path.join(qd, f'.tmp-{name}')
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        os.replace(tmp, os.path.join(qd, name))
        log(f"slack via certwire (live): event {rec['event_id']} queued")
    else:
        qd = os.path.join(relay, 'queue-certwire.d')
        os.makedirs(qd, exist_ok=True)
        name = f"{rec['ts']}-{rec['event_id']}.knock"
        with open(os.path.join(qd, name), 'w', encoding='utf-8') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        _append(os.path.join(relay, 'certwire-events.jsonl'), rec)
        log(f"slack via certwire (shadow): event {rec['event_id']} recorded")


# ---------- react outbox ----------

async def react_outbox_loop(app):
    """Relay reaction requests to the provisor (2026-10-24: the
    per-muse bot apps are gone; the provisor fires reactions.add
    as the proxy bot). Relay processes spool {channel, ts, name}
    into the react outbox via proxy_react.py; claim by rename,
    post to the provisor at /slack/react, write the ack status
    back as <id>.result (null when the post got no ack)."""
    outbox = os.path.expanduser(CFG.get(
        'react_outbox', '~/workspace/slack-relay/react-outbox'))
    while True:
        try:
            os.makedirs(outbox, exist_ok=True)
            for name in sorted(os.listdir(outbox)):
                if not name.endswith('.json') or name.startswith('.tmp-'):
                    continue
                src = os.path.join(outbox, name)
                claim = src + '.sending'
                try:
                    os.replace(src, claim)
                except OSError:
                    continue
                rid = name[:-len('.json')]
                status = None
                try:
                    req = json.load(open(claim))
                    body = json.dumps({'channel': req['channel'],
                                       'ts': req['ts'],
                                       'name': req['name']})
                    status = await app.post(CFG['provisor_address'],
                                            '/slack/react', body,
                                            ack=True, timeout=10)
                    log(f'react outbox: {rid} {req["name"]} on '
                        f'{req["ts"]} -> ack {status}')
                except Exception as e:
                    log(f'react outbox: {rid} failed: {e}')
                try:
                    rtmp = os.path.join(outbox, f'{rid}.result.tmp')
                    with open(rtmp, 'w', encoding='utf-8') as f:
                        f.write(json.dumps({'status': status}))
                    os.replace(rtmp, os.path.join(outbox, f'{rid}.result'))
                except OSError:
                    pass
                try:
                    os.unlink(claim)
                except OSError:
                    pass
        except Exception as e:
            log(f'react outbox loop: {e}')
        await asyncio.sleep(0.5)


# ---------- main ----------

CW = None


async def _register_until_ok():
    """Registration must not be a startup dependency: the proxied
    path to the provisor drops connections at random ages. Retry
    until the first success; after that, re-registration happens
    only through the key-failure recovery path in slack_handler."""
    while not STATE['registered']:
        if STATE['key'] is not None and _route_confirmed(STATE['last_rereg']):
            STATE['registered'] = True
            log('slack route register: prior attempt confirmed landed')
            break
        try:
            register_route()
        except Exception as e:
            log(f'slack route register failed: {e}; retrying in 20s')
            await asyncio.sleep(20)


async def main():
    global CW
    asyncio.ensure_future(_register_until_ok())
    CW = CertwireClient(CFG.get('certwire_url', 'wss://certwire.net'),
                        CERT_TEXT, sign, log=log)
    app = AppClient(CW, log=log)
    asyncio.ensure_future(react_outbox_loop(app))
    app.route(CFG['knockwire_address'], f"/{CFG['guid']}/", knock_handler)
    app.legacy_route(CFG['provisor_address'], slack_handler)
    CW.whitelist_names = list(CFG.get('whitelist_names', []))
    log(f"serving as {MY_ADDRESS}; knock sender {CFG['knockwire_address']}; "
        f"slack provisor {CFG['provisor_address']}; "
        f"slack mode {CFG.get('slack_mode', 'shadow')}")
    await CW.run()


if __name__ == '__main__':
    asyncio.run(main())

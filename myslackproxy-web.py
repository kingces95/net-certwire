#!/usr/bin/env python3
"""myslackproxy web service — the provisor's public face on :18080.

Routes:
  GET /                      the listening placeholder, unchanged
  GET /auth/slack/install    mint a single-use state, 302 to Slack OAuth
  GET /auth/slack/callback   validate state, exchange the code at
                             oauth.v2.access, upsert the installation
                             (Codex's CRUD model), small result page
  GET /v1/routes             public route list (address, fingerprint,
                             identities, key epoch per registered muse)
  GET /v1/cert               this provisor's own certmint domain cert,
                             verbatim — adopters fetch it here instead of
                             receiving it out of band; it is public,
                             issuer-signed material, so the mirror needs
                             no trust. Read from disk per request so a
                             cert renewal takes effect with no restart.

Installation records live in /etc/myslackproxy/installations.json,
keyed by enterprise_id + team_id + is_enterprise_install. Bot tokens
are Fernet-encrypted at rest under a host keyfile; the journal and
pages never see token material. Pending install states are memory-only
(a restart forgets them, like certmint's web sessions)."""
import datetime, html, json, os, secrets, threading, urllib.parse, urllib.request
import http.server

ENV_PATH = os.environ.get('MYSLACKPROXY_ENV', '/etc/myslackproxy/slack.env')
STORE_PATH = os.environ.get('MYSLACKPROXY_STORE', '/etc/myslackproxy/installations.json')
KEY_PATH = os.environ.get('MYSLACKPROXY_KEY', '/etc/myslackproxy/store-key')
ROUTES_PATH = os.environ.get('MYSLACKPROXY_ROUTES', '/etc/myslackproxy/routes.json')
OWN_CERT_PATH = os.environ.get('MYSLACKPROXY_OWN_CERT', '/etc/myslackproxy/domain-cert.txt')
MINT_BASE = 'https://certmint.net'
PUBLIC_BASE = 'https://myslackproxy.net'
REDIRECT_URI = PUBLIC_BASE + '/auth/slack/callback'
BOT_SCOPES = 'channels:history,groups:history,im:history,mpim:history,users:read'
UA = 'myslackproxy-web/1.0'
STATE_TTL = 600

LOCK = threading.Lock()
PENDING = {}  # state -> expiry epoch


def load_env(path):
    cfg = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                cfg[k.strip()] = v.strip()
    return cfg


CFG = load_env(ENV_PATH)


def fernet():
    from cryptography.fernet import Fernet
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, 'wb') as f:
            f.write(Fernet.generate_key())
        os.chmod(KEY_PATH, 0o600)
    with open(KEY_PATH, 'rb') as f:
        return Fernet(f.read().strip())


def load_store():
    try:
        with open(STORE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def save_store(store):
    tmp = STORE_PATH + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(store, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STORE_PATH)


def slack_post(url, form, token=None):
    data = urllib.parse.urlencode(form).encode()
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UA}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# ---------- muse route registration ----------
ROUTE_NONCES = {}  # nonce -> expiry epoch

# Sealed transport keys (certwire payload encryption): a registering
# muse may seal a symmetric transport key to the provisor's cert key
# and include it in the registration. The blob is held ONLY in this
# process's memory — never written to disk — and is handed to the
# bridge exactly once (take-once) via the token-guarded internal
# endpoint below. A registration without a sealed key clears any
# previously held blob for that route (no stale-key resurrection).
SEALED_KEYS = {}  # key fingerprint -> {'sealed': b64, 'epoch': int, 'address': str}
INTERNAL_TOKEN_PATH = os.environ.get(
    'MYSLACKPROXY_INTERNAL_TOKEN', '/etc/myslackproxy/internal.token')


def _internal_ok(handler):
    try:
        with open(INTERNAL_TOKEN_PATH) as f:
            token = f.read().strip()
    except Exception:
        return False
    given = handler.headers.get('X-Internal-Token') or ''
    return bool(token) and secrets.compare_digest(given, token)


def _mint_material():
    import base64, struct
    req = urllib.request.Request(MINT_BASE + '/pubkey', headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        info = json.loads(r.read())
    blob = base64.b64decode(info['key'].split()[1])
    ln, = struct.unpack('>I', blob[:4]); off = 4 + ln
    ln2, = struct.unpack('>I', blob[off:off + 4])
    raw = blob[off + 4:off + 4 + ln2]
    req = urllib.request.Request(MINT_BASE + '/revoked', headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        revoked = set(r.read().decode().split())
    return raw, revoked


def _parse_cert(text):
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


def _key_raw(key_line):
    import base64, struct
    blob = base64.b64decode(key_line.strip().split()[1])
    ln, = struct.unpack('>I', blob[:4]); off = 4 + ln
    ln2, = struct.unpack('>I', blob[off:off + 4])
    return blob[off + 4:off + 4 + ln2]


def load_routes():
    try:
        with open(ROUTES_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def save_routes(routes):
    tmp = ROUTES_PATH + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(routes, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, ROUTES_PATH)


def page(title, inner):
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<title>{title}</title></head><body>{inner}</body></html>').encode()


class H(http.server.BaseHTTPRequestHandler):
    def log_request(self, code='-', size='-'):
        # Path only, never the query string: the callback's query
        # carries a (single-use, by then spent) OAuth code.
        path = urllib.parse.urlparse(self.path).path
        print(f'{self.address_string()} "{self.command} {path}" {code} -', flush=True)

    def _send(self, code, body, ctype='text/html; charset=utf-8', extra=None):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path, qs = parsed.path, urllib.parse.parse_qs(parsed.query)

        if path == '/':
            self._send(200, b'myslackproxy is listening.\n', 'text/plain; charset=utf-8')
            return

        if path == '/v1/routes/challenge':
            nonce = secrets.token_urlsafe(32)
            with LOCK:
                ROUTE_NONCES[nonce] = datetime.datetime.now(
                    datetime.timezone.utc).timestamp() + 300
            self._send(200, json.dumps({
                'nonce': nonce,
                'signing_string': f'myslackproxy-route-v1\n<serial>\n{nonce}'}).encode(),
                'application/json')
            return

        if path == '/v1/cert':
            try:
                with open(OWN_CERT_PATH, 'rb') as f:
                    cert = f.read()
            except OSError:
                self._send(404, b'provisor cert not available\n',
                           'text/plain; charset=utf-8')
                return
            self._send(200, cert, 'text/plain; charset=utf-8')
            return

        if path == '/v1/routes':
            with LOCK:
                routes = load_routes()
            public = [{'address': r['address'], 'fingerprint': fp,
                       'identities': r['identities'], 'updated_at': r['updated_at'],
                       'key_epoch': r.get('key_epoch')}
                      for fp, r in routes.items()]
            self._send(200, json.dumps({'routes': public}).encode(), 'application/json')
            return

        if path == '/internal/sealed-key':
            if not _internal_ok(self):
                self._json(403, {'error': 'internal token required'})
                return
            fp = (qs.get('fingerprint') or [''])[0]
            try:
                epoch = int((qs.get('epoch') or ['0'])[0])
            except ValueError:
                epoch = 0
            with LOCK:
                held = SEALED_KEYS.get(fp)
                if held and held['epoch'] == epoch:
                    del SEALED_KEYS[fp]
                else:
                    held = None
            if held is None:
                self._json(404, {'error': 'no sealed key held for that route/epoch'})
                return
            print(f"sealed key handed to bridge: {held['address']} epoch {epoch}", flush=True)
            self._json(200, {'sealed': held['sealed'], 'epoch': epoch,
                             'address': held['address']})
            return

        if path == '/auth/slack/install':
            state = secrets.token_urlsafe(24)
            with LOCK:
                PENDING[state] = datetime.datetime.now(datetime.timezone.utc).timestamp() + STATE_TTL
            params = urllib.parse.urlencode({
                'client_id': CFG['SLACK_CLIENT_ID'],
                'scope': BOT_SCOPES,
                'redirect_uri': REDIRECT_URI,
                'state': state,
            })
            self._send(302, b'', extra=[('Location', f'https://slack.com/oauth/v2/authorize?{params}')])
            return

        if path == '/auth/slack/callback':
            code = (qs.get('code') or [''])[0]
            state = (qs.get('state') or [''])[0]
            if (qs.get('error') or [''])[0]:
                self._send(400, page('myslackproxy', '<h1>myslackproxy</h1><p>Slack declined the install.</p>'))
                return
            with LOCK:
                exp = PENDING.pop(state, None)
            if not code or exp is None or exp < datetime.datetime.now(datetime.timezone.utc).timestamp():
                self._send(400, page('myslackproxy', '<h1>myslackproxy</h1><p>Invalid or expired install state. Start again from the install link.</p>'))
                return
            try:
                resp = slack_post('https://slack.com/api/oauth.v2.access', {
                    'client_id': CFG['SLACK_CLIENT_ID'],
                    'client_secret': CFG['SLACK_CLIENT_SECRET'],
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                })
            except Exception as e:
                print(f'oauth exchange failed: {type(e).__name__}', flush=True)
                self._send(502, page('myslackproxy', '<h1>myslackproxy</h1><p>The token exchange with Slack failed. Nothing was stored.</p>'))
                return
            if not resp.get('ok'):
                print(f"oauth exchange refused: {resp.get('error')}", flush=True)
                self._send(502, page('myslackproxy', '<h1>myslackproxy</h1><p>Slack refused the token exchange. Nothing was stored.</p>'))
                return
            team = resp.get('team') or {}
            ent = resp.get('enterprise') or {}
            is_ent = bool(resp.get('is_enterprise_install'))
            key = f"{ent.get('id') or ''}|{team.get('id')}|{is_ent}"
            record = {
                'team_id': team.get('id'),
                'team_name': team.get('name'),
                'enterprise_id': ent.get('id'),
                'enterprise_name': ent.get('name'),
                'is_enterprise_install': is_ent,
                'bot_user_id': resp.get('bot_user_id'),
                'scope': resp.get('scope'),
                'installer_user_id': (resp.get('authed_user') or {}).get('id'),
                'access_token_enc': fernet().encrypt(resp['access_token'].encode()).decode(),
                'updated_at': now_iso(),
            }
            try:
                test = slack_post('https://slack.com/api/auth.test', {}, token=resp['access_token'])
                record['auth_test_ok'] = bool(test.get('ok'))
                if test.get('ok'):
                    record['team_name'] = test.get('team') or record['team_name']
                    record['team_id'] = test.get('team_id') or record['team_id']
            except Exception:
                record['auth_test_ok'] = False
            with LOCK:
                store = load_store()
                record['installed_at'] = store.get(key, {}).get('installed_at', record['updated_at'])
                store[key] = record
                save_store(store)
            print(f"installation upserted: team={record['team_id']} "
                  f"auth_test_ok={record['auth_test_ok']}", flush=True)
            self._send(200, page('myslackproxy',
                f"<h1>myslackproxy</h1><p>Installed for <b>{html.escape(record['team_name'] or record['team_id'] or 'your workspace')}</b>. "
                f"You can close this page.</p>"))
            return

        self._send(404, b'not found\n', 'text/plain; charset=utf-8')

    def _body_json(self):
        ln = int(self.headers.get('Content-Length') or 0)
        if ln <= 0 or ln > 65536:
            return {}
        try:
            return json.loads(self.rfile.read(ln).decode())
        except Exception:
            return {}

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode(), 'application/json')

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == '/internal/purge':
            if not _internal_ok(self):
                self._json(403, {'error': 'internal token required'})
                return
            with LOCK:
                SEALED_KEYS.clear()
            print('sealed keys purged (bridge request)', flush=True)
            self._json(200, {'purged': True})
            return
        if path != '/v1/routes':
            self._send(404, b'not found\n', 'text/plain; charset=utf-8')
            return
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        req = self._body_json()
        cert_text = req.get('cert') or ''
        nonce = req.get('nonce') or ''
        try:
            fields, identities, body, sig = _parse_cert(cert_text)
        except Exception:
            self._json(400, {'error': 'unparseable cert'})
            return
        with LOCK:
            exp = ROUTE_NONCES.pop(nonce, None)
        if exp is None or exp < datetime.datetime.now(datetime.timezone.utc).timestamp():
            self._json(400, {'error': 'unknown or expired challenge'})
            return
        try:
            mint_raw, revoked = _mint_material()
            Ed25519PublicKey.from_public_bytes(mint_raw).verify(base64.b64decode(sig), body)
        except Exception:
            self._json(400, {'error': 'mint signature does not verify'})
            return
        serial = fields.get('serial', '')
        if serial in revoked:
            self._json(403, {'error': 'cert revoked'})
            return
        if fields.get('expires', '') < now_iso():
            self._json(403, {'error': 'cert expired'})
            return
        try:
            Ed25519PublicKey.from_public_bytes(_key_raw(fields['key'])).verify(
                base64.b64decode(req.get('signature') or ''),
                f"myslackproxy-route-v1\n{serial}\n{nonce}".encode())
        except Exception:
            self._json(403, {'error': 'possession proof does not verify'})
            return
        slack_ids = []
        for ident in identities:
            kv = dict(t.split('=', 1) for t in ident.split() if '=' in t)
            if kv.get('provider') == 'slack':
                slack_ids.append({'team': kv.get('team'), 'sub': kv.get('sub')})
        if not slack_ids:
            self._json(400, {'error': 'cert carries no slack identity'})
            return
        address = f"{fields['issuer']}/{serial}"
        fp = fields['key-fingerprint']
        record = {'address': address, 'serial': int(serial), 'issuer': fields['issuer'],
                  'identities': slack_ids, 'cert': cert_text, 'updated_at': now_iso()}
        sealed = req.get('transport_key_sealed')
        with LOCK:
            routes = load_routes()
            if isinstance(sealed, str) and 0 < len(sealed) <= 512:
                epoch = (routes.get(fp) or {}).get('key_epoch', 0) + 1
                SEALED_KEYS[fp] = {'sealed': sealed, 'epoch': epoch, 'address': address}
                record['key_epoch'] = epoch
            else:
                SEALED_KEYS.pop(fp, None)
            routes[fp] = record
            save_routes(routes)
        print(f"route registered: {address} -> {slack_ids} "
              f"key_epoch={record.get('key_epoch')}", flush=True)
        self._json(201, {'address': address, 'identities': slack_ids,
                         'key_epoch': record.get('key_epoch')})

    do_HEAD = do_GET


if __name__ == '__main__':
    http.server.ThreadingHTTPServer(('127.0.0.1', 18080), H).serve_forever()

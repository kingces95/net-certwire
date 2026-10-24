#!/usr/bin/env python3
"""certwire app layer v1 — POSTs with certified paths.

certwire (the net layer, certwire.py) routes opaque payloads between
cert-bound connections and holds no policy: it authenticates a
connection once at open, binds the cert's address, and drops whatever
is addressed to an unbound destination. Everything else — what a
payload MEANS — is this layer, implemented in the endpoint's client
library so the router can stay bytes-only.

The protocol is deliberately HTTP-shaped, minus the transport:

  post frame   {"app": "post", "v": 1, "id": <id>, "method": "POST",
                "path": "/<guid>/gmail", "body": "", "ack": true}
  ack frame    {"app": "ack", "v": 1, "id": <id>, "status": 200}

A "certified path" is a path delivered over a cert-bound connection:
the path itself is not signed, but the pair (sender cert address,
path) is trustworthy as a unit, so admission is a LOCAL table of
(sender address, path prefix) -> handler — the firewall lives on the
muse endpoint, never in the router. (The router's per-connection
whitelist is the coarse gate beneath it: a destination whitelists
sender names — domain, address or key fingerprint — before this
layer ever sees a frame.)

A post that asks for an ack gets one after its handler runs, and the
ack's status is the handler's return value (200 default). The ack is
the delivery signal store-and-forward senders retry against: the
knockwire mailbox flusher, for instance, treats a post as delivered
only when the ack comes back, exactly as it treats an HTTP 200 from
the tunnel demux today. A post resolves as failed when the router
reports the destination unbound ('dropped') or the ack times out.

Payloads that are not app frames are "legacy": they are routed to a
per-sender legacy handler. The myslackproxy bridge predates this
layer and sends bare encrypted envelopes; the muse-side Slack
handler is a legacy handler keyed by the provisor's address.

Bodies are strings in v1. Opaque bytes ride as a JSON value by
convention of the individual app (the Slack app seals its event
JSON into an envelope dict as its body); the frame does not care.
"""
import asyncio, secrets


class AppClient:
    """Wraps a CertwireClient with framing, admission and demux."""

    def __init__(self, cw, log=print):
        self.cw = cw
        self.log = log
        self.rules = []    # (sender_address, path_prefix, handler)
        self.legacy = {}   # sender_address -> handler(frm, payload)
        self.pending = {}  # frame id -> (asyncio.Future, to_address)
        cw.on_deliver = self._on_deliver
        prev_dropped = cw.on_dropped

        async def _dropped(to):
            self._fail_pending(to)
            if prev_dropped is not None:
                r = prev_dropped(to)
                if asyncio.iscoroutine(r):
                    await r
        cw.on_dropped = _dropped

    # ---------- receiving ----------

    def route(self, sender, path_prefix, handler):
        """Admit posts from `sender` (a cert address) whose path
        starts with `path_prefix`. handler(frm, method, path, body)
        returns an HTTP-ish status int for the ack (or None = 200)."""
        self.rules.append((sender, path_prefix, handler))

    def legacy_route(self, sender, handler):
        """Handle non-app-frame payloads from `sender`.
        handler(frm, payload) may be sync or async."""
        self.legacy[sender] = handler

    async def _on_deliver(self, frm, payload):
        if isinstance(payload, dict) and payload.get('app') == 'ack':
            ent = self.pending.pop(payload.get('id') or '', None)
            if ent is not None and not ent[0].done():
                ent[0].set_result(payload.get('status'))
            return
        if isinstance(payload, dict) and payload.get('app') == 'post':
            status = 404
            for sender, prefix, handler in self.rules:
                if frm == sender and (payload.get('path') or '').startswith(prefix):
                    try:
                        r = handler(frm, payload.get('method') or 'POST',
                                    payload.get('path') or '',
                                    payload.get('body') or '')
                        if asyncio.iscoroutine(r):
                            r = await r
                        status = 200 if r is None else int(r)
                    except Exception as e:
                        self.log(f'app: handler error for {payload.get("path")}: {e}')
                        status = 500
                    break
            else:
                self.log(f'app: post from {frm} to {payload.get("path")} not admitted')
            if payload.get('ack'):
                await self.cw.send(frm, {'app': 'ack', 'v': 1,
                                         'id': payload.get('id'),
                                         'status': status})
            return
        handler = self.legacy.get(frm)
        if handler is not None:
            r = handler(frm, payload)
            if asyncio.iscoroutine(r):
                await r
        else:
            self.log(f'app: unhandled legacy payload from {frm}')

    # ---------- sending ----------

    def _fail_pending(self, to):
        for fid, (fut, dest) in list(self.pending.items()):
            if dest == to and not fut.done():
                fut.set_result(None)
                del self.pending[fid]

    async def post(self, to, path, body='', method='POST', ack=True,
                   timeout=10):
        """Send one app post. Returns the ack status (int), or None
        when the destination is unbound, the send could not be made,
        or no ack arrived within `timeout` seconds."""
        fid = secrets.token_hex(8)
        fut = None
        if ack:
            fut = asyncio.get_running_loop().create_future()
            self.pending[fid] = (fut, to)
        await self.cw.send(to, {'app': 'post', 'v': 1, 'id': fid,
                                'method': method, 'path': path,
                                'body': body, 'ack': ack})
        if not ack:
            return 0
        try:
            return await asyncio.wait_for(fut, timeout)
        except (asyncio.TimeoutError, TimeoutError):
            self.pending.pop(fid, None)
            return None

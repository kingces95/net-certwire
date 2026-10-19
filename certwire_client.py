#!/usr/bin/env python3
"""certwire client: opens the long connection, authenticates once with
a certmint cert (possession proof over the server nonce), and then
sends/receives payloads on the binding. Routing is UDP-like: a send
either dispatches on the live connection or is dropped — nothing is
queued across an outage and there is no delivery guarantee (receivers
dedupe on their own ids, e.g. Slack event_id). The whitelist is
connection state: it is (re)sent automatically after every open."""
import asyncio, json

import websockets


def parse_cert_fields(cert_text):
    fields = {}
    for ln in cert_text.strip().split('\n'):
        if ': ' in ln:
            k, v = ln.split(': ', 1)
            fields[k] = v
    return fields


class CertwireClient:
    def __init__(self, url, cert_text, sign, on_deliver=None, log=print, on_dropped=None):
        self.url = url
        self.cert_text = cert_text
        self.serial = parse_cert_fields(cert_text)['serial']
        self.sign = sign            # bytes -> base64 signature string
        self.on_deliver = on_deliver or (lambda frm, payload: None)
        self.on_dropped = on_dropped  # async/sync hook(to_address) on router 'dropped'
        self.log = log
        self.address = None
        self.whitelist_names = []
        self.queue = asyncio.Queue()
        self.ws = None

    async def whitelist(self, names):
        self.whitelist_names = list(names)
        if self.ws is not None and self.address:
            await self.ws.send(json.dumps({'op': 'whitelist', 'names': self.whitelist_names}))

    async def send(self, to, payload):
        if self.ws is None or not self.address:
            self.log(f'certwire: dropped -> {to}: not connected')
            return
        await self.queue.put({'op': 'send', 'to': to, 'payload': payload})

    async def _session(self):
        async with websockets.connect(self.url, ping_interval=30, ping_timeout=60) as ws:
            self.ws = ws
            first = json.loads(await ws.recv())
            if first.get('op') != 'challenge':
                raise RuntimeError(f'unexpected greeting: {first}')
            sig = self.sign(f"certwire-open-v1\n{self.serial}\n{first['nonce']}".encode())
            await ws.send(json.dumps({'op': 'open', 'cert': self.cert_text, 'signature': sig}))

            async def writer():
                while True:
                    frame = await self.queue.get()
                    await ws.send(json.dumps(frame))

            wtask = asyncio.ensure_future(writer())
            try:
                async for raw in ws:
                    msg = json.loads(raw)
                    op = msg.get('op')
                    if op == 'open_ok':
                        self.address = msg['address']
                        self.log(f"certwire: bound as {self.address}")
                        if self.whitelist_names:
                            await ws.send(json.dumps({'op': 'whitelist',
                                                      'names': self.whitelist_names}))
                    elif op == 'deliver':
                        await self.on_deliver(msg.get('from'), msg.get('payload'))
                    elif op in ('sent', 'dropped'):
                        self.log(f"certwire: {op} -> {msg.get('to')}")
                        if op == 'dropped' and self.on_dropped is not None:
                            r = self.on_dropped(msg.get('to'))
                            if asyncio.iscoroutine(r):
                                await r
                    elif op in ('refused', 'error'):
                        self.log(f"certwire: {op}: {msg.get('error')}")
            finally:
                wtask.cancel()
                self.ws = None
                dropped = 0
                while not self.queue.empty():
                    self.queue.get_nowait()
                    dropped += 1
                if dropped:
                    self.log(f'certwire: dropped {dropped} queued frame(s) on disconnect')

    async def reconnect(self):
        """Close the live connection; run() reopens it. Used by the
        key-lifecycle policy: a dropped payload kills the key and the
        connection it rode on."""
        if self.ws is not None:
            try:
                await self.ws.close()
            except Exception:
                pass

    async def run(self):
        while True:
            try:
                await self._session()
            except Exception as e:
                self.log(f'certwire: connection error: {type(e).__name__}: {e}')
            self.address = None
            await asyncio.sleep(5)

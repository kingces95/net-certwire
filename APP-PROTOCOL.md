# certwire app layer v1 — POSTs with certified paths

Status: implemented and live for Hal's muse, 2026-10-23
(`certwire_app.py`, `muse-appd.py` in this repo; `kw-bridge.py` in
net-knockwire). certwire itself is unchanged.

## Layering

certwire is the net layer: it authenticates a connection once at
open (certmint cert + possession proof), binds the cert's address
(`issuer/serial`), routes opaque payloads between bound addresses,
admits a payload only when the destination's whitelist names the
sender (by domain, address, or key fingerprint), and drops —
never queues — anything else. It holds no other policy.

Everything above that is the app layer, and it lives in the
endpoint's client library, not in the router:

- framing: what a payload means;
- demux: one cert-bound connection, many logical flows, separated
  by path;
- admission: the firewall table of (sender cert address, path
  prefix) -> handler, held by the receiving muse;
- semantics: what a sender asserts by posting, and the ack/retry
  contract between the two endpoints.

A muse can therefore advertise more than one cert, speak a
different app protocol to a different peer, or replace this
protocol entirely, without the fabric noticing.

## Frames

Payloads are JSON objects. Two frame types:

```
post   {"app": "post", "v": 1, "id": <id>, "method": "POST",
        "path": "/<guid>/gmail", "body": "", "ack": true}
ack    {"app": "ack", "v": 1, "id": <id>, "status": 200}
```

A **certified path** is a path delivered over a cert-bound
connection. The path is not itself signed; the pair (sender cert
address, path) is trustworthy as a unit, and that pair is what the
admission table keys on.

A post with `"ack": true` is answered after its handler runs; the
ack's status is the handler's return value (200 by default, 404
when no rule admits the (sender, path), 500 on handler error). The
ack is the delivery signal a store-and-forward sender retries
against: the router's own `sent` report only proves the destination
was bound, not that its app accepted anything. A post resolves as
failed when the router reports the destination unbound or the ack
times out (10s in the reference client).

Bodies are strings in v1. An app that needs opaque bytes seals or
encodes them as a JSON value by its own convention (the Slack app
seals its event JSON into the certwire_crypto envelope as its
body); the frame does not care.

## Legacy payloads

Payloads that are not app frames are routed by sender address to a
legacy handler. The myslackproxy bridge predates this layer and
sends bare encrypted envelopes; the muse-side Slack handler is a
legacy handler keyed by the provisor's address
(`certmint.net/22`). New apps should speak frames.

## Apps running on it

### knock (knockwire -> muse)

Sender: knockwire's domain cert, `certmint.net/25`
(domain `knockwire.net`). Path: `/<guid>/<service...>`, body
empty, method preserved from the original webhook.

The muse admits the knockwire address at prefix `/<its guid>/`
only. The handler writes one knock file per post into the local
knock spool (`~/.knockwire/queue/<service>/`), byte-identical to
what the SSH-tunnel demux writes (`"<METHOD> /<service>\n"`), and
returns 200. The channel hooks cannot tell the two transports
apart.

knockwire's side is split: kw-web keeps its stdlib HTTP shape and
calls the `kw-bridge` companion over loopback; the bridge holds
the certwire connection and turns each delivery into an app post,
reporting success only on the muse's ack. Registrations carry the
muse's certwire address (kw-client advertises it at registration
from its id cert), and kw-web's `deliver()` tries certwire first
for opted-in services (default `gmail,gmailwork,test`) with the
bound tunnel port as fallback. The per-guid mailbox and its
flusher use the same `deliver()`, so the store-and-forward
semantics built for the tunnel carry over unchanged: spool on
failure, flush FIFO on recovery, ack as the success signal at
every hop.

### slack (provisor -> muse, legacy)

Sender: myslackproxy's domain cert, `certmint.net/22`. The bridge
forwards Slack events authored by the muse's owner (route match on
team + user) as certwire_crypto envelopes sealed under the
transport key the muse sealed to the provisor at route
registration. The muse-side handler decrypts, translates the
event subset ({type, channel, user, text, ts} + event_id) into
the Slack relay's record shape, and writes it to the relay spool.

Known limits of the provisor feed, by the bridge's design: it
carries only owner-authored events in channels the provisor's
Slack app occupies, and the event subset has no channel_type or
thread_ts. It is a wake feed, not a transcript feed; the relay's
socket-mode transport remains the full-fidelity source until a
cutover is chosen with those limits in view.

## What a new muse adopts

1. `certwire_client.py` + `certwire_app.py` (this repo).
2. A daemon in the shape of `muse-appd.py`: load the id cert,
   register app routes, set the router whitelist to the sender
   names it admits (domains are convenient), and register
   (sender address, path prefix) handlers.
3. For knock delivery: kw-client already advertises the certwire
   address at registration; nothing else changes.

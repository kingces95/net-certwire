# certwire — authenticated message routing, with encrypted payloads

certwire routes payloads between parties who hold certmint
certificates. Connections authenticate **once** at open (cert +
possession proof over a server nonce) and bind the cert's address
(`issuer/serial`); payloads then route on that binding with no
per-message verification. A payload is delivered only when the
destination's whitelist admits the sender (by the sender cert's
domain, address, or key fingerprint).

Routing is **UDP-like**: a payload either dispatches to a currently
bound destination or is dropped on the spot. certwire keeps no
queue and offers no delivery guarantee; receivers dedupe on their
own ids (e.g. Slack `event_id`).

## Files

| file | role |
|---|---|
| `certwire.py` | the router (reference deployment: its own VM, `wss://certwire.net`, loopback origin behind a Cloudflare tunnel) |
| `certwire_client.py` | shared client: open/authenticate once, auto-reconnect, whitelist re-sent per connection |
| `certwire_crypto.py` | the payload-encryption scheme (below) |
| `myslackproxy-web.py` | reference provisor web service: Slack OAuth install door + muse route-registration door |
| `slack-listener.py` | reference provisor bridge: Slack Socket Mode → encrypted certwire payloads |
| `muse-client.py` | reference muse client: `serve` = register (with sealed key) + listen + decrypt |
| `certwire_app.py` | the app layer (below): (path, body) framing, admission table, demux, ack frames |
| `muse-appd.py` | reference muse app daemon: one cert-bound connection carrying the knock + Slack apps |
| `APP-PROTOCOL.md` | the app-layer protocol spec |
| `test_certwire_crypto.py` | unit tests for the crypto module |

## App layer (2026-10-23)

certwire routes bytes and holds no policy; the protocol spoken
over it lives in the endpoints' client library. The app layer is
**POSTs with certified paths**: a frame carries a method, a path
and a body over a cert-bound connection, admission is the
receiving muse's local table of (sender cert address, path
prefix) -> handler, and an optional ack frame is the delivery
signal store-and-forward senders retry against. Live apps: the
knockwire knock (guid paths -> the local knock spool, acked) and
the Slack provisor feed (legacy encrypted envelopes). See
`APP-PROTOCOL.md`.

## Payload encryption (Chris's design, 2026-10-19)

The router is trusted to route, not to read. Payloads are encrypted
end to end between the provisor and the muse; certwire (and every
relay in the path, including Cloudflare) sees only envelopes.

**Key establishment — at registration, sealed under the cert keys.**
The muse generates a fresh 32-byte transport key and seals it to
the provisor in the registration request itself:

- The seal is a NaCl box (XSalsa20-Poly1305 over X25519 DH) between
  the two parties' cert keys, converted Ed25519→Curve25519 with
  libsodium's standard conversion. Only the provisor can open it;
  the box authenticates the muse's cert key as sender. The key can
  therefore cross any infrastructure — the registration door is
  Cloudflare-fronted — as ciphertext.
- The sealed plaintext is `key || SHA-256(context)`, where the
  context is `(muse cert address, provisor domain, team)`. A blob
  replayed into a different registration fails on open.
- The provisor's web service holds the sealed blob **in memory
  only** (never on disk), tagged with a per-route `key_epoch` that
  increments on every keyed registration. The bridge takes each
  blob exactly once over a token-guarded loopback endpoint and
  opens it into its own memory.

**Payloads.** Per-direction keys are derived from the transport key
by HKDF-SHA256 (info = direction label + context). Envelopes are
NaCl secretbox ciphertexts; the sender and destination cert
addresses ride as associated data and are checked on decrypt. A
muse verifies it is talking to the intended provisor, and vice
versa, on every payload — independent of the router's `from`.

**Lifecycle — policy, not protocol.** There is deliberately no
handshake and no forward secrecy machinery (the static-DH seal
cannot offer it: a recorded blob plus a later provisor-key
compromise would expose that registration's key). Instead the
exposure is bounded by key lifetime:

- Keys live **only in process memory** on both ends. Nothing is
  ever persisted, so any recycle of either endpoint destroys them.
  A bridge restart additionally purges sealed blobs still held by
  the web service.
- At the **first dropped payload**, the provisor deletes its key
  copy and closes its certwire connection.
- A payload the muse **cannot decrypt** is dropped, and the muse
  **re-registers** with a fresh key — debounced to at most once per
  180s. Re-registration is the single recovery verb for every key
  failure mode: stale key, lost key, suspected compromise.
- With no live key, the bridge drops events rather than sending
  them in the clear. There is no plaintext fallback and no
  downgrade path.

**Upgrade path.** If forward secrecy is ever required, replace the
static seal with an ephemeral-DH handshake (Noise_IK pattern) at
connection time; the lifecycle policy above is unchanged.

## Proven live (2026-10-19, myslackproxy ↔ Hal)

1. `muse-client.py serve` registered with a sealed key
   (`key_epoch` 1); the bridge opened it and forwarded a Slack
   event as an envelope; the muse decrypted the full event.
2. Muse killed → next payload dropped at the router → bridge
   deleted the key and closed/reopened its certwire connection.
3. Next event dropped bridge-side: no live key, awaiting
   re-registration.
4. Muse re-registered (epoch 2, fresh key) → bridge opened the
   new key → encrypted delivery resumed.

#!/usr/bin/env python3
"""certwire payload encryption — the reference implementation.

Scheme (Chris's design, 2026-10-19): the symmetric transport key is
created by the MUSE at registration time and sealed to the provisor
under the two parties' cert keys, so the key itself can cross
untrusted infrastructure (the Cloudflare-fronted registration door,
certwire, any relay) as ciphertext. Everything after that is policy,
not protocol:

  * keys live ONLY in memory — nothing about them is ever written
    to disk, so a recycle of either endpoint process destroys them;
  * the provisor deletes its copy at the first dropped payload and
    closes its certwire connection (the router's 'dropped'
    disposition is the trigger);
  * a payload the muse cannot decrypt is dropped, and the muse
    re-registers (debounced) — re-registration is the single
    recovery verb for every key failure mode.

Cryptography, deliberately boring (PyNaCl/libsodium only):

  * Cert keys are Ed25519 signing keys. For the seal they are
    converted to Curve25519 with libsodium's standard conversion
    (SigningKey.to_curve25519_private_key / VerifyKey.
    to_curve25519_public_key). The seal is a NaCl box (XSalsa20-
    Poly1305 over an X25519 DH of the converted keys): only the
    provisor can open it, and the box authenticates that it was
    sealed under the muse's cert key.
  * The sealed plaintext is key(32) || SHA-256(context), where the
    context binds the key to (muse cert address, provisor domain,
    team): a blob replayed into a different registration fails the
    context check on open.
  * Payloads use per-direction keys derived from the transport key
    by HKDF-SHA256 (info = direction label + context), encrypted
    with NaCl secretbox (XSalsa20-Poly1305, random 24-byte nonce),
    with the sender and destination cert addresses as associated
    data folded into the plaintext envelope check on decrypt.

Known, accepted limitation: the seal is static-key DH, so it has no
forward secrecy — a recorded registration blob plus a later
compromise of the provisor's private key would expose that
registration's transport key. The lifecycle policy above (memory-
only keys, death on recycle and on first drop, re-registration as
the universal recovery) is what bounds that exposure in this
design; an ephemeral-DH handshake (Noise_IK) is the upgrade path
if forward secrecy is ever required.
"""
import base64, hashlib, hmac as hmac_mod, os, struct

import nacl.public, nacl.secret, nacl.signing

KEY_LEN = 32
DIRECTIONS = ('provisor-to-muse', 'muse-to-provisor')


def openssh_raw(key_line):
    """Raw 32-byte Ed25519 public key from an OpenSSH key line."""
    blob = base64.b64decode(key_line.strip().split()[1])
    ln, = struct.unpack('>I', blob[:4]); off = 4 + ln
    ln2, = struct.unpack('>I', blob[off:off + 4])
    return blob[off + 4:off + 4 + ln2]


def _curve_pub(ed_pub_raw):
    return nacl.signing.VerifyKey(ed_pub_raw).to_curve25519_public_key()


def _curve_priv(ed_priv_raw):
    return nacl.signing.SigningKey(ed_priv_raw).to_curve25519_private_key()


def context_string(muse_address, provisor_domain, team):
    return f'certwire-transport-key-v1\n{muse_address}\n{provisor_domain}\n{team}'


def seal_transport_key(key, ctx, muse_ed_priv_raw, provisor_ed_pub_raw):
    """Seal a 32-byte transport key from the muse to the provisor.
    Returns the base64 blob (nonce || ciphertext) for the
    registration request."""
    if len(key) != KEY_LEN:
        raise ValueError('transport key must be 32 bytes')
    box = nacl.public.Box(_curve_priv(muse_ed_priv_raw), _curve_pub(provisor_ed_pub_raw))
    plain = key + hashlib.sha256(ctx.encode()).digest()
    return base64.b64encode(bytes(box.encrypt(plain))).decode()


def open_transport_key(blob_b64, ctx, provisor_ed_priv_raw, muse_ed_pub_raw):
    """Open a sealed transport key on the provisor. Raises on any
    failure (wrong key, wrong context, tampering)."""
    box = nacl.public.Box(_curve_priv(provisor_ed_priv_raw), _curve_pub(muse_ed_pub_raw))
    plain = box.decrypt(base64.b64decode(blob_b64))
    key, digest = plain[:KEY_LEN], plain[KEY_LEN:]
    if len(plain) != KEY_LEN + 32 or not hmac_mod.compare_digest(
            digest, hashlib.sha256(ctx.encode()).digest()):
        raise ValueError('transport key context mismatch')
    return key


def _hkdf_sha256(ikm, info, length=KEY_LEN, salt=None):
    if salt is None:
        salt = b'\x00' * 32
    prk = hmac_mod.new(salt, ikm, hashlib.sha256).digest()
    okm, t, counter = b'', b'', 1
    while len(okm) < length:
        t = hmac_mod.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def direction_key(transport_key, direction, ctx):
    if direction not in DIRECTIONS:
        raise ValueError(f'unknown direction {direction!r}')
    return _hkdf_sha256(transport_key, f'{direction}\n{ctx}'.encode())


def encrypt_payload(dir_key, plaintext, aad):
    """Encrypt one payload. Returns the envelope dict that travels as
    the certwire payload (opaque to the router)."""
    box = nacl.secret.SecretBox(dir_key)
    enc = box.encrypt(plaintext, os.urandom(nacl.secret.SecretBox.NONCE_SIZE))
    return {'enc': 'v1', 'aad': aad,
            'blob': base64.b64encode(bytes(enc)).decode()}


def decrypt_payload(dir_key, envelope, aad):
    """Decrypt one envelope. Raises on wrong key, tampering, or an
    associated-data mismatch."""
    if not isinstance(envelope, dict) or envelope.get('enc') != 'v1':
        raise ValueError('not an encrypted envelope')
    if envelope.get('aad') != aad:
        raise ValueError('envelope associated-data mismatch')
    box = nacl.secret.SecretBox(dir_key)
    return box.decrypt(base64.b64decode(envelope['blob']))


def aad_string(sender_address, dest_address):
    return f'{sender_address}\n{dest_address}'

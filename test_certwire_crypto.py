#!/usr/bin/env python3
"""Unit tests for certwire_crypto — run with any venv that has
pynacl + cryptography:  python3 test_certwire_crypto.py"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import certwire_crypto as cc
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

raw = lambda k: k.private_bytes(serialization.Encoding.Raw,
                                serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
pub = lambda k: k.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw)


def expect_fail(fn, name):
    try:
        fn()
    except Exception:
        return
    raise AssertionError(f'should have failed: {name}')


def main():
    muse, prov, other = (Ed25519PrivateKey.generate() for _ in range(3))
    ctx = cc.context_string('certmint.ai/18', 'myslackproxy.net', 'T0C8FJ78NJD')
    K = os.urandom(32)

    blob = cc.seal_transport_key(K, ctx, raw(muse), pub(prov))
    assert cc.open_transport_key(blob, ctx, raw(prov), pub(muse)) == K
    print('seal/open roundtrip ok')

    expect_fail(lambda: cc.open_transport_key(
        blob, cc.context_string('certmint.ai/99', 'myslackproxy.net',
                                'T0C8FJ78NJD'), raw(prov), pub(muse)), 'wrong ctx')
    expect_fail(lambda: cc.open_transport_key(blob, ctx, raw(other), pub(muse)),
                'wrong recipient')
    expect_fail(lambda: cc.open_transport_key(blob, ctx, raw(prov), pub(other)),
                'wrong sender')
    print('wrong ctx/recipient/sender all rejected')

    dk_down = cc.direction_key(K, 'provisor-to-muse', ctx)
    dk_up = cc.direction_key(K, 'muse-to-provisor', ctx)
    assert dk_down != dk_up and len(dk_down) == 32
    aad = cc.aad_string('certmint.net/22', 'certmint.ai/18')
    env = cc.encrypt_payload(dk_down, b'{"kind":"slack_event"}', aad)
    assert cc.decrypt_payload(dk_down, env, aad) == b'{"kind":"slack_event"}'
    expect_fail(lambda: cc.decrypt_payload(dk_up, env, aad), 'wrong direction')
    expect_fail(lambda: cc.decrypt_payload(
        dk_down, env, 'certmint.net/22\ncertmint.ai/99'), 'aad mismatch')
    expect_fail(lambda: cc.decrypt_payload(
        dk_down, dict(env, blob=env['blob'][:-4] + 'AAAA'), aad), 'tampered')
    print('payload roundtrip + direction/aad/tamper all correct')
    print('ALL TESTS PASS')


if __name__ == '__main__':
    main()

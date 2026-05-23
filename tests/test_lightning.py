"""L402 challenge / authorize roundtrip with mock LN backend."""

import time

from veritas.lightning import (
    DeterministicMockBackend,
    Macaroon,
    authorize,
    make_challenge,
)


SECRET = b"test-secret-32-bytes-or-whatever"


def test_macaroon_tag_roundtrip():
    m = Macaroon.create(SECRET, "id1", "ph"*16, ["resource=premium"])
    assert m.verify_tag(SECRET)
    # Tamper.
    bad = Macaroon(m.identifier, m.payment_hash, m.caveats + ["c2=evil"], m.tag)
    assert bad.verify_tag(SECRET) is False


def test_l402_full_flow():
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="premium:m1", amount_msat=500)
    # Client "pays" by asking the demo helper for the preimage.
    preimage_hex = ln.reveal_preimage(chal.payment_hash)
    auth = f"L402 {chal.macaroon_token}:{preimage_hex}"
    assert authorize(SECRET, ln, auth_header_value=auth, resource_id="premium:m1")


def test_l402_rejects_wrong_preimage():
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="r1")
    auth = f"L402 {chal.macaroon_token}:{'00'*32}"
    assert not authorize(SECRET, ln, auth_header_value=auth, resource_id="r1")


def test_l402_rejects_resource_mismatch():
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="r1")
    preimage_hex = ln.reveal_preimage(chal.payment_hash)
    auth = f"L402 {chal.macaroon_token}:{preimage_hex}"
    assert not authorize(SECRET, ln, auth_header_value=auth, resource_id="r2")

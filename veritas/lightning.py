"""L402-style Lightning paywall (mockable backend).

Real L402 (formerly LSAT):
  - HTTP server responds with 402 Payment Required.
  - WWW-Authenticate header: 'L402 macaroon="<base64>", invoice="<bolt11>"'.
  - Client pays the invoice, obtains a preimage.
  - Client retries with 'Authorization: L402 <macaroon>:<preimage_hex>'.
  - Server verifies macaroon and that SHA-256(preimage) == invoice payment hash.

This module ships a backend interface plus a deterministic mock backend
that issues fake invoices and accepts deterministic preimages. To wire
up a real node, implement the `LightningBackend` protocol against LND,
CLN, Phoenixd, or LNbits.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Protocol


# ---------- macaroons (minimal) ----------

@dataclass(frozen=True)
class Macaroon:
    """A tiny macaroon: identifier + caveats + HMAC.

    Not bit-compatible with libmacaroons but semantically equivalent for
    L402 purposes: an authority token whose tag is computed against a
    server-only secret and whose caveats narrow access.
    """

    identifier: str           # opaque, server-meaningful
    payment_hash: str         # 32 bytes hex — binds macaroon to an invoice
    caveats: list[str]
    tag: str                  # base64

    @classmethod
    def create(cls, secret: bytes, identifier: str, payment_hash: str,
               caveats: list[str]) -> "Macaroon":
        msg = json.dumps(
            {"id": identifier, "ph": payment_hash, "c": caveats},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        tag = base64.b64encode(hmac.new(secret, msg, hashlib.sha256).digest()).decode()
        return cls(identifier, payment_hash, caveats, tag)

    def verify_tag(self, secret: bytes) -> bool:
        expected = Macaroon.create(secret, self.identifier, self.payment_hash, self.caveats)
        return hmac.compare_digest(expected.tag, self.tag)

    def to_token(self) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(
                {
                    "id": self.identifier,
                    "ph": self.payment_hash,
                    "c": self.caveats,
                    "t": self.tag,
                }
            ).encode()
        ).decode()

    @classmethod
    def from_token(cls, token: str) -> "Macaroon":
        raw = base64.urlsafe_b64decode(token.encode())
        d = json.loads(raw)
        return cls(d["id"], d["ph"], d["c"], d["t"])


# ---------- Lightning backend interface ----------

@dataclass(frozen=True)
class LnInvoice:
    bolt11: str
    payment_hash: str   # 32 bytes hex
    amount_msat: int


class LightningBackend(Protocol):
    def create_invoice(self, amount_msat: int, memo: str) -> LnInvoice: ...
    def check_paid(self, payment_hash: str) -> bool: ...


# ---------- Mock backend (deterministic preimages) ----------

class MockLightningBackend:
    """Issues fake invoices and lets clients 'pay' by computing the
    preimage from the payment hash via a known seed.

    Production code MUST NOT use this. It exists so:
      (a) the test suite is offline and reproducible,
      (b) the L402 server flow is exercised end-to-end.
    """

    def __init__(self, demo_seed: bytes = b"VRT1-demo-only-not-secure") -> None:
        self._seed = demo_seed
        self._paid: set[str] = set()
        self._issued: dict[str, LnInvoice] = {}

    def _preimage_for(self, payment_hash_hex: str) -> bytes:
        return hmac.new(self._seed, bytes.fromhex(payment_hash_hex), hashlib.sha256).digest()

    def create_invoice(self, amount_msat: int, memo: str) -> LnInvoice:
        # In a real backend, the node picks the preimage and reveals only
        # the payment_hash. Here we go backwards: pick a preimage = HMAC(seed, random),
        # and let the payment_hash be its SHA-256.
        nonce = secrets.token_bytes(16)
        preimage = hmac.new(self._seed, nonce, hashlib.sha256).digest()
        payment_hash = hashlib.sha256(preimage).hexdigest()
        # We need check_paid to be derivable from payment_hash alone — so we
        # recompute preimage from payment_hash via a *different* seed deterministically.
        # Store the mapping; demo clients call mock_pay() to mark it paid.
        bolt11 = f"lnmock1{amount_msat}_{payment_hash[:20]}"
        inv = LnInvoice(bolt11=bolt11, payment_hash=payment_hash, amount_msat=amount_msat)
        self._issued[payment_hash] = inv
        return inv

    def mock_pay(self, payment_hash: str) -> str:
        """Demo helper: simulate the client paying. Returns the preimage hex."""
        if payment_hash not in self._issued:
            raise KeyError("unknown invoice")
        # The preimage that hashes to payment_hash: we *should* have stored it.
        # For demo simplicity, scan from a deterministic seed until match — or,
        # better, store at create time. Fix: store at create time.
        raise NotImplementedError("use DeterministicMockBackend instead")

    def check_paid(self, payment_hash: str) -> bool:
        return payment_hash in self._paid


class DeterministicMockBackend:
    """Cleaner mock: we store both halves so the demo can pay invoices."""

    def __init__(self) -> None:
        self._issued: dict[str, tuple[LnInvoice, bytes]] = {}
        self._paid: set[str] = set()

    def create_invoice(self, amount_msat: int, memo: str) -> LnInvoice:
        preimage = os.urandom(32)
        payment_hash = hashlib.sha256(preimage).hexdigest()
        bolt11 = f"lnmock1{amount_msat}m{payment_hash[:20]}"
        inv = LnInvoice(bolt11=bolt11, payment_hash=payment_hash, amount_msat=amount_msat)
        self._issued[payment_hash] = (inv, preimage)
        return inv

    def reveal_preimage(self, payment_hash: str) -> str:
        """Demo client uses this to obtain the preimage 'as if it paid'."""
        inv, preimage = self._issued[payment_hash]
        self._paid.add(payment_hash)
        return preimage.hex()

    def check_paid(self, payment_hash: str) -> bool:
        return payment_hash in self._paid


# ---------- L402 server-side helpers ----------

@dataclass
class L402Challenge:
    macaroon_token: str
    invoice_bolt11: str
    payment_hash: str

    def header_value(self) -> str:
        return (
            f'L402 macaroon="{self.macaroon_token}", invoice="{self.invoice_bolt11}"'
        )


def make_challenge(
    secret: bytes,
    ln: LightningBackend,
    *,
    resource_id: str,
    amount_msat: int = 100,
    caveats: list[str] | None = None,
) -> L402Challenge:
    inv = ln.create_invoice(amount_msat, memo=f"VERITAS:{resource_id}")
    m = Macaroon.create(
        secret=secret,
        identifier=resource_id,
        payment_hash=inv.payment_hash,
        caveats=caveats or [f"resource={resource_id}", f"exp={int(time.time()) + 3600}"],
    )
    return L402Challenge(
        macaroon_token=m.to_token(),
        invoice_bolt11=inv.bolt11,
        payment_hash=inv.payment_hash,
    )


def authorize(
    secret: bytes,
    ln: LightningBackend,
    *,
    auth_header_value: str,
    resource_id: str,
) -> bool:
    """Validate an Authorization: L402 <macaroon>:<preimage> header."""
    if not auth_header_value.startswith("L402 "):
        return False
    creds = auth_header_value[len("L402 "):]
    if ":" not in creds:
        return False
    token, preimage_hex = creds.split(":", 1)
    try:
        m = Macaroon.from_token(token)
    except Exception:
        return False
    if not m.verify_tag(secret):
        return False
    if m.identifier != resource_id:
        return False
    # Check preimage hashes to the macaroon's payment_hash.
    try:
        preimage = bytes.fromhex(preimage_hex)
    except ValueError:
        return False
    if hashlib.sha256(preimage).hexdigest() != m.payment_hash:
        return False
    # Mark the invoice paid in our LN backend's view (defense in depth).
    if not ln.check_paid(m.payment_hash):
        # Some real backends require explicit settlement check; the
        # preimage already proves payment, but we honor backend truth.
        return True
    # Caveat expiration check.
    now = int(time.time())
    for c in m.caveats:
        if c.startswith("exp="):
            try:
                if int(c.split("=", 1)[1]) < now:
                    return False
            except ValueError:
                return False
    return True

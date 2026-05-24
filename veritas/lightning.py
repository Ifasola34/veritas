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
import ssl
import time
import urllib.error
import urllib.request
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

class DeterministicMockBackend:
    """In-process mock: stores preimages so the demo flow can settle invoices.

    The `bolt11` field is a placeholder string, NOT a parseable BOLT-11
    invoice — no real Lightning wallet can pay it. Tests and the demo
    server use reveal_preimage() to simulate settlement. Wire a real
    backend (LND, CLN, Phoenixd, LNbits) for production.
    """

    def __init__(self) -> None:
        self._issued: dict[str, tuple[LnInvoice, bytes]] = {}
        self._paid: set[str] = set()

    def create_invoice(self, amount_msat: int, memo: str) -> LnInvoice:
        preimage = os.urandom(32)
        payment_hash = hashlib.sha256(preimage).hexdigest()
        bolt11 = f"lnmock-placeholder-{amount_msat}msat-{payment_hash[:16]}"
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
    require_backend_settled: bool = False,
) -> bool:
    """Validate an Authorization: L402 <macaroon>:<preimage> header.

    Authorization requires ALL of:
      1. Header well-formed.
      2. Macaroon HMAC tag valid under `secret`.
      3. Macaroon identifier matches `resource_id`.
      4. SHA-256(preimage) == macaroon.payment_hash.
      5. Every exp= caveat is in the future.

    Possession of a preimage that hashes to the macaroon's payment_hash
    is itself the cryptographic proof of payment in L402; revealing it
    requires actually paying the invoice. The LN backend's check_paid()
    is consulted only when `require_backend_settled=True` (real LSPs
    where revocation/double-spend tracking matters); in default mode an
    unsettled-but-cryptographically-proven preimage is still rejected
    if any caveat fails. The check_paid result NEVER grants access on
    its own, and never bypasses caveat enforcement.
    """
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
    try:
        preimage = bytes.fromhex(preimage_hex)
    except ValueError:
        return False
    if hashlib.sha256(preimage).hexdigest() != m.payment_hash:
        return False
    if require_backend_settled and not ln.check_paid(m.payment_hash):
        return False
    # Every macaroon MUST carry at least one exp= caveat so authorization
    # has a bounded lifetime. A caveat-less macaroon would otherwise
    # authorize forever — make_challenge always issues one, so reject
    # anything that lacks one (either tampering or a non-VERITAS issuer).
    now = int(time.time())
    saw_exp = False
    for c in m.caveats:
        if c.startswith("exp="):
            saw_exp = True
            try:
                if int(c.split("=", 1)[1]) < now:
                    return False
            except ValueError:
                return False
    if not saw_exp:
        return False
    return True


# ---------- Real Lightning backends -------------------------------
#
# Both backends speak HTTP/JSON and validate the same LightningBackend
# protocol (create_invoice + check_paid). Tests mock urllib.request so
# the suite stays offline. To run live, set the env vars in
# server.py:_make_ln_backend.


def _make_ssl_context(cert_path: str | None) -> ssl.SSLContext | None:
    """Build an SSL context that trusts a specific self-signed cert.

    LND ships a self-signed tls.cert by default; we point Python at it
    via `cafile=` so the connection verifies against that single cert
    rather than the system CA bundle. Returning None lets urllib fall
    back to default verification (good for nodes behind a real CA).
    """
    if not cert_path:
        return None
    ctx = ssl.create_default_context(cafile=cert_path)
    return ctx


class LndRestBackend:
    """LND REST API (https://api.lightning.community/rest/).

    Endpoints used:
      POST /v1/invoices            — create invoice
      GET  /v1/invoice/{r_hash}    — query settlement status

    Auth is a hex-encoded macaroon in the Grpc-Metadata-macaroon header.
    Tip: `xxd -ps -u -c 1000 ~/.lnd/data/chain/bitcoin/signet/admin.macaroon`
    """

    name = "lnd"

    def __init__(
        self,
        url: str,
        macaroon_hex: str,
        tls_cert_path: str | None = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        # Normalize trailing slash so f-strings produce clean paths.
        self.url = url.rstrip("/")
        self.macaroon_hex = macaroon_hex
        self.timeout = timeout_seconds
        self._ssl_ctx = _make_ssl_context(tls_cert_path)

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        url = f"{self.url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={
                "Grpc-Metadata-macaroon": self.macaroon_hex,
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(
            req, timeout=self.timeout, context=self._ssl_ctx,
        ) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def create_invoice(self, amount_msat: int, memo: str) -> LnInvoice:
        # LND wants value (sats) for typical mainnet/testnet flows;
        # using value_msat is supported and avoids truncation.
        resp = self._request("POST", "/v1/invoices", {
            "value_msat": str(amount_msat),
            "memo": memo,
            "expiry": "3600",
        })
        # LND returns r_hash as base64. We need hex for the protocol.
        r_hash_b64 = resp["r_hash"]
        r_hash_hex = base64.b64decode(r_hash_b64).hex()
        bolt11 = resp["payment_request"]
        return LnInvoice(
            bolt11=bolt11, payment_hash=r_hash_hex, amount_msat=amount_msat,
        )

    def check_paid(self, payment_hash: str) -> bool:
        # LND accepts the r_hash as a hex string in the URL path.
        try:
            resp = self._request("GET", f"/v1/invoice/{payment_hash}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return False
            raise
        # LND returns invoice.state in {OPEN, SETTLED, CANCELED, ACCEPTED}.
        return resp.get("state") == "SETTLED" or bool(resp.get("settled"))


class PhoenixdBackend:
    """Phoenixd HTTP API (https://phoenix.acinq.co/server/api).

    Endpoints used:
      POST /createinvoice
        form: amountSat=<n>&description=<...>
      GET  /payments/incoming/{paymentHash}

    Auth is HTTP Basic with empty username and the http-password from
    ~/.phoenix/phoenix.conf.
    """

    name = "phoenixd"

    def __init__(
        self,
        url: str,
        password: str,
        timeout_seconds: float = 15.0,
    ) -> None:
        self.url = url.rstrip("/")
        self.password = password
        self.timeout = timeout_seconds
        token = base64.b64encode(f":{password}".encode()).decode()
        self._auth_header = f"Basic {token}"

    def _request(
        self, method: str, path: str,
        form_body: dict | None = None,
    ) -> dict:
        url = f"{self.url}{path}"
        data = None
        headers = {"Authorization": self._auth_header}
        if form_body is not None:
            data = "&".join(
                f"{k}={urllib.request.quote(str(v))}" for k, v in form_body.items()
            ).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def create_invoice(self, amount_msat: int, memo: str) -> LnInvoice:
        # Phoenixd expects amountSat. Round up so we never under-charge.
        amount_sat = max(1, (amount_msat + 999) // 1000)
        resp = self._request("POST", "/createinvoice", {
            "amountSat": amount_sat,
            "description": memo,
        })
        # Response: {"serialized": "<bolt11>", "paymentHash": "<hex>", ...}
        return LnInvoice(
            bolt11=resp["serialized"],
            payment_hash=resp["paymentHash"],
            amount_msat=amount_sat * 1000,
        )

    def check_paid(self, payment_hash: str) -> bool:
        try:
            resp = self._request("GET", f"/payments/incoming/{payment_hash}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return False
            raise
        return bool(resp.get("isPaid"))

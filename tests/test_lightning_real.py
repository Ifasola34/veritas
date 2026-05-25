"""LND + Phoenixd backend tests — all HTTP calls mocked.

These exercise the real-backend request/response shapes (URLs, headers,
auth, payload formats) without ever touching a live node. The factory
in server.py is also exercised end-to-end so a missing env var fails
loudly at startup.
"""

from __future__ import annotations

import base64
import io
import json
import os
import urllib.error
from unittest.mock import patch

import pytest

from veritas.lightning import LndRestBackend, PhoenixdBackend


class _FakeResp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): self.close()


# ---------- LndRestBackend -----------------------------------------


def test_lnd_create_invoice_request_shape():
    r_hash = bytes.fromhex("aa" * 32)
    resp = json.dumps({
        "r_hash": base64.b64encode(r_hash).decode(),
        "payment_request": "lnbc1pmocked...",
    }).encode()
    with patch("veritas.lightning.urllib.request.urlopen",
               return_value=_FakeResp(resp)) as mock_open:
        b = LndRestBackend(url="https://node:8080/", macaroon_hex="cafe")
        inv = b.create_invoice(amount_msat=1000, memo="test")

    sent = mock_open.call_args[0][0]
    assert sent.full_url == "https://node:8080/v1/invoices"
    assert sent.headers.get("Grpc-metadata-macaroon") == "cafe"
    body = json.loads(sent.data.decode())
    assert body == {"value_msat": "1000", "memo": "test", "expiry": "3600"}
    assert inv.bolt11 == "lnbc1pmocked..."
    assert inv.payment_hash == "aa" * 32
    assert inv.amount_msat == 1000


def test_lnd_check_paid_settled():
    resp = json.dumps({"state": "SETTLED", "settled": True}).encode()
    with patch("veritas.lightning.urllib.request.urlopen",
               return_value=_FakeResp(resp)) as mock_open:
        b = LndRestBackend(url="https://node:8080", macaroon_hex="cafe")
        ok = b.check_paid("aa" * 32)
    sent = mock_open.call_args[0][0]
    assert sent.full_url == f"https://node:8080/v1/invoice/{'aa'*32}"
    assert sent.get_method() == "GET"
    assert ok is True


def test_lnd_check_paid_open():
    resp = json.dumps({"state": "OPEN", "settled": False}).encode()
    with patch("veritas.lightning.urllib.request.urlopen",
               return_value=_FakeResp(resp)):
        ok = LndRestBackend(url="https://n", macaroon_hex="ca").check_paid("00" * 32)
    assert ok is False


def test_lnd_check_paid_404_treated_as_unpaid():
    err = urllib.error.HTTPError(
        url="https://n/v1/invoice/00", code=404, msg="Not Found",
        hdrs={}, fp=io.BytesIO(b"{}"),
    )
    with patch("veritas.lightning.urllib.request.urlopen", side_effect=err):
        ok = LndRestBackend(url="https://n", macaroon_hex="ca").check_paid("00" * 32)
    assert ok is False


def test_lnd_check_paid_other_http_error_wrapped_as_runtime_error():
    """Round-3 fix: non-404 HTTP errors are wrapped in RuntimeError with
    the status code in the message, so FastAPI surfaces a clean error
    instead of escaping urllib's exception hierarchy."""
    err = urllib.error.HTTPError(
        url="https://n/v1/invoice/00", code=500, msg="Internal Error",
        hdrs={}, fp=io.BytesIO(b"{}"),
    )
    with patch("veritas.lightning.urllib.request.urlopen", side_effect=err):
        with pytest.raises(RuntimeError, match="HTTP 500"):
            LndRestBackend(url="https://n", macaroon_hex="ca").check_paid("00" * 32)


# ---------- PhoenixdBackend ----------------------------------------


def test_phoenixd_create_invoice_request_shape():
    resp = json.dumps({
        "serialized": "lnbc1psmoothmocked",
        "paymentHash": "bb" * 32,
    }).encode()
    with patch("veritas.lightning.urllib.request.urlopen",
               return_value=_FakeResp(resp)) as mock_open:
        b = PhoenixdBackend(url="http://127.0.0.1:9740/", password="hunter2")
        inv = b.create_invoice(amount_msat=2500, memo="VERITAS test")

    sent = mock_open.call_args[0][0]
    assert sent.full_url == "http://127.0.0.1:9740/createinvoice"
    assert sent.get_method() == "POST"
    # Basic auth header: base64(":hunter2")
    expected_auth = "Basic " + base64.b64encode(b":hunter2").decode()
    assert sent.headers.get("Authorization") == expected_auth
    # Form body: amountSat must round 2500 msat up to 3 sat.
    body = sent.data.decode()
    assert "amountSat=3" in body
    assert "description=VERITAS%20test" in body
    assert inv.bolt11 == "lnbc1psmoothmocked"
    assert inv.payment_hash == "bb" * 32
    # amount_msat reflects rounded-up sat value.
    assert inv.amount_msat == 3000


def test_phoenixd_check_paid_true():
    resp = json.dumps({"isPaid": True}).encode()
    with patch("veritas.lightning.urllib.request.urlopen",
               return_value=_FakeResp(resp)):
        ok = PhoenixdBackend(url="http://n", password="p").check_paid("bb" * 32)
    assert ok is True


def test_phoenixd_check_paid_false():
    resp = json.dumps({"isPaid": False}).encode()
    with patch("veritas.lightning.urllib.request.urlopen",
               return_value=_FakeResp(resp)):
        ok = PhoenixdBackend(url="http://n", password="p").check_paid("00" * 32)
    assert ok is False


def test_phoenixd_check_paid_404_treated_as_unpaid():
    err = urllib.error.HTTPError(
        url="http://n/payments/incoming/00", code=404, msg="Not Found",
        hdrs={}, fp=io.BytesIO(b"{}"),
    )
    with patch("veritas.lightning.urllib.request.urlopen", side_effect=err):
        ok = PhoenixdBackend(url="http://n", password="p").check_paid("00" * 32)
    assert ok is False


# ---------- env-driven factory in server.py ------------------------


def test_factory_mock_default():
    for k in ("VERITAS_LN_BACKEND", "VERITAS_ENV"):
        os.environ.pop(k, None)
    from veritas.server import _make_ln_backend
    from veritas.lightning import DeterministicMockBackend
    assert isinstance(_make_ln_backend(), DeterministicMockBackend)


def test_factory_mock_rejected_in_prod():
    os.environ["VERITAS_ENV"] = "prod"
    os.environ.pop("VERITAS_LN_BACKEND", None)
    try:
        from veritas.server import _make_ln_backend
        with pytest.raises(RuntimeError, match="refusing"):
            _make_ln_backend()
    finally:
        del os.environ["VERITAS_ENV"]


def test_factory_lnd_requires_env():
    os.environ["VERITAS_LN_BACKEND"] = "lnd"
    for k in ("VERITAS_LND_URL", "VERITAS_LND_MACAROON"):
        os.environ.pop(k, None)
    try:
        from veritas.server import _make_ln_backend
        with pytest.raises(RuntimeError, match="VERITAS_LND_URL"):
            _make_ln_backend()
    finally:
        del os.environ["VERITAS_LN_BACKEND"]


def test_factory_lnd_constructs():
    os.environ["VERITAS_LN_BACKEND"] = "lnd"
    os.environ["VERITAS_LND_URL"] = "https://lnd.local:8080"
    os.environ["VERITAS_LND_MACAROON"] = "cafe" * 64
    try:
        from veritas.server import _make_ln_backend
        b = _make_ln_backend()
        assert isinstance(b, LndRestBackend)
        assert b.url == "https://lnd.local:8080"
        assert b.macaroon_hex.startswith("cafe")
    finally:
        for k in ("VERITAS_LN_BACKEND", "VERITAS_LND_URL", "VERITAS_LND_MACAROON"):
            del os.environ[k]


def test_factory_phoenixd_requires_env():
    os.environ["VERITAS_LN_BACKEND"] = "phoenixd"
    for k in ("VERITAS_PHOENIXD_URL", "VERITAS_PHOENIXD_PASSWORD"):
        os.environ.pop(k, None)
    try:
        from veritas.server import _make_ln_backend
        with pytest.raises(RuntimeError, match="VERITAS_PHOENIXD_URL"):
            _make_ln_backend()
    finally:
        del os.environ["VERITAS_LN_BACKEND"]


def test_factory_phoenixd_constructs():
    os.environ["VERITAS_LN_BACKEND"] = "phoenixd"
    os.environ["VERITAS_PHOENIXD_URL"] = "http://127.0.0.1:9740"
    os.environ["VERITAS_PHOENIXD_PASSWORD"] = "secretpw"
    try:
        from veritas.server import _make_ln_backend
        b = _make_ln_backend()
        assert isinstance(b, PhoenixdBackend)
        assert b.url == "http://127.0.0.1:9740"
        assert b.password == "secretpw"
    finally:
        for k in ("VERITAS_LN_BACKEND", "VERITAS_PHOENIXD_URL",
                  "VERITAS_PHOENIXD_PASSWORD"):
            del os.environ[k]


def test_factory_unknown_backend_rejected():
    os.environ["VERITAS_LN_BACKEND"] = "cln"
    try:
        from veritas.server import _make_ln_backend
        with pytest.raises(RuntimeError, match="unsupported"):
            _make_ln_backend()
    finally:
        del os.environ["VERITAS_LN_BACKEND"]

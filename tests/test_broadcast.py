"""Broadcaster tests — no real network calls.

Mempool.space and bitcoind RPC are exercised through urllib.request.urlopen
patched to return canned bytes/HTTPError, so the test suite stays offline
and reproducible. The env-driven factory is also exercised end-to-end.
"""

from __future__ import annotations

import io
import json
import os
import urllib.error
from unittest.mock import patch

import pytest

from veritas.broadcast import (
    BitcoindRpcBroadcaster,
    BroadcastResult,
    MempoolSpaceBroadcaster,
    NullBroadcaster,
    make_broadcaster,
)


# ---------- NullBroadcaster ----------------------------------------


def test_null_broadcaster_always_ok():
    r = NullBroadcaster().broadcast("deadbeef")
    assert r.ok is True
    assert r.txid is None
    assert r.error is None
    assert r.backend == "null"


# ---------- MempoolSpaceBroadcaster --------------------------------


class _FakeResp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): self.close()


def test_mempool_broadcaster_signet_url():
    b = MempoolSpaceBroadcaster(network="signet")
    assert "signet" in b.url
    assert b.name == "mempool.space:signet"


def test_mempool_broadcaster_unsupported_network():
    with pytest.raises(ValueError):
        MempoolSpaceBroadcaster(network="liquid")


def test_mempool_broadcaster_success():
    fake_txid = "aa" * 32
    with patch("veritas.broadcast.urllib.request.urlopen",
               return_value=_FakeResp(fake_txid.encode())):
        r = MempoolSpaceBroadcaster(network="signet").broadcast("0100" * 50)
    assert r.ok is True
    assert r.txid == fake_txid
    assert r.error is None


def test_mempool_broadcaster_http_error_returns_failure():
    err = urllib.error.HTTPError(
        url="https://mempool.space/signet/api/tx",
        code=400,
        msg="Bad Request",
        hdrs={},
        fp=io.BytesIO(b"bad-txns-inputs-missingorspent"),
    )
    with patch("veritas.broadcast.urllib.request.urlopen", side_effect=err):
        r = MempoolSpaceBroadcaster(network="signet").broadcast("00" * 10)
    assert r.ok is False
    assert r.txid is None
    assert "HTTP 400" in r.error


def test_mempool_broadcaster_network_failure():
    with patch("veritas.broadcast.urllib.request.urlopen",
               side_effect=urllib.error.URLError("DNS lookup failed")):
        r = MempoolSpaceBroadcaster(network="signet").broadcast("00" * 10)
    assert r.ok is False
    assert "network error" in r.error


# ---------- BitcoindRpcBroadcaster ---------------------------------


def test_bitcoind_rpc_success_with_auth():
    resp = json.dumps({"result": "cc" * 32, "error": None, "id": "veritas"}).encode()
    with patch("veritas.broadcast.urllib.request.urlopen",
               return_value=_FakeResp(resp)) as mock_open:
        b = BitcoindRpcBroadcaster(
            "http://127.0.0.1:18332", rpc_auth=("u", "p"),
        )
        r = b.broadcast("0100abcdef")

    # Verify Authorization header was attached.
    sent_req = mock_open.call_args[0][0]
    assert sent_req.headers.get("Authorization", "").startswith("Basic ")
    # Verify the JSON-RPC body.
    body = json.loads(sent_req.data.decode())
    assert body["method"] == "sendrawtransaction"
    assert body["params"] == ["0100abcdef"]

    assert r.ok is True
    assert r.txid == "cc" * 32


def test_bitcoind_rpc_returns_error_block():
    resp = json.dumps({
        "result": None,
        "error": {"code": -25, "message": "Missing inputs"},
        "id": "veritas",
    }).encode()
    with patch("veritas.broadcast.urllib.request.urlopen",
               return_value=_FakeResp(resp)):
        r = BitcoindRpcBroadcaster("http://127.0.0.1:18332").broadcast("00")
    assert r.ok is False
    assert "Missing inputs" in r.error


def test_bitcoind_rpc_transport_error():
    with patch("veritas.broadcast.urllib.request.urlopen",
               side_effect=urllib.error.URLError("connection refused")):
        r = BitcoindRpcBroadcaster("http://127.0.0.1:18332").broadcast("00")
    assert r.ok is False
    assert "transport error" in r.error


# ---------- env-driven factory -------------------------------------


def test_factory_default_disabled():
    for k in ("VERITAS_ANCHOR_BROADCAST", "VERITAS_BROADCASTER",
              "VERITAS_BTC_NETWORK", "VERITAS_BTC_RPC_URL"):
        os.environ.pop(k, None)
    b = make_broadcaster()
    assert isinstance(b, NullBroadcaster)


def test_factory_mempool_signet():
    os.environ["VERITAS_ANCHOR_BROADCAST"] = "1"
    os.environ["VERITAS_BROADCASTER"] = "mempool"
    os.environ["VERITAS_BTC_NETWORK"] = "signet"
    try:
        b = make_broadcaster()
        assert isinstance(b, MempoolSpaceBroadcaster)
        assert b.network == "signet"
    finally:
        del os.environ["VERITAS_ANCHOR_BROADCAST"]
        del os.environ["VERITAS_BROADCASTER"]
        del os.environ["VERITAS_BTC_NETWORK"]


def test_factory_bitcoind_requires_url():
    os.environ["VERITAS_ANCHOR_BROADCAST"] = "1"
    os.environ["VERITAS_BROADCASTER"] = "bitcoind"
    os.environ.pop("VERITAS_BTC_RPC_URL", None)
    try:
        with pytest.raises(RuntimeError, match="VERITAS_BTC_RPC_URL"):
            make_broadcaster()
    finally:
        del os.environ["VERITAS_ANCHOR_BROADCAST"]
        del os.environ["VERITAS_BROADCASTER"]


def test_factory_bitcoind_with_auth():
    os.environ["VERITAS_ANCHOR_BROADCAST"] = "1"
    os.environ["VERITAS_BROADCASTER"] = "bitcoind"
    os.environ["VERITAS_BTC_RPC_URL"] = "http://127.0.0.1:18332"
    os.environ["VERITAS_BTC_RPC_USER"] = "alice"
    os.environ["VERITAS_BTC_RPC_PASS"] = "secret"
    try:
        b = make_broadcaster()
        assert isinstance(b, BitcoindRpcBroadcaster)
        assert b.rpc_auth == ("alice", "secret")
    finally:
        for k in ("VERITAS_ANCHOR_BROADCAST", "VERITAS_BROADCASTER",
                  "VERITAS_BTC_RPC_URL", "VERITAS_BTC_RPC_USER",
                  "VERITAS_BTC_RPC_PASS"):
            del os.environ[k]


def test_factory_rejects_unknown_backend():
    os.environ["VERITAS_ANCHOR_BROADCAST"] = "1"
    os.environ["VERITAS_BROADCASTER"] = "blockstream"
    try:
        with pytest.raises(RuntimeError, match="unsupported"):
            make_broadcaster()
    finally:
        del os.environ["VERITAS_ANCHOR_BROADCAST"]
        del os.environ["VERITAS_BROADCASTER"]


# ---------- end-to-end integration with Oracle ---------------------


def test_oracle_invokes_broadcaster_on_close(tmp_path):
    from coincurve import PrivateKey
    from veritas.anchor import Utxo, derive_anchor_pubkey
    from veritas.crypto import OracleKey, derive_anchor_key
    from veritas.oracle import Oracle, OracleConfig

    okey = OracleKey.generate()
    anchor_priv = derive_anchor_key(okey)
    utxo = Utxo(
        txid="ab" * 32, vout=0, value_sats=10_000,
        pubkey_compressed=derive_anchor_pubkey(anchor_priv),
    )
    sent_hex: list[str] = []

    class _RecordingBroadcaster:
        name = "recording"
        def broadcast(self, raw_hex):
            sent_hex.append(raw_hex)
            return BroadcastResult(ok=True, txid="ee" * 32, error=None, backend=self.name)

    oracle = Oracle(okey, OracleConfig(
        data_dir=tmp_path,
        anchor_utxo=utxo,
        broadcaster=_RecordingBroadcaster(),
    ))
    oracle.attest("veritas.sentiment.keyword.v1", "bullish")
    e = oracle.close_epoch()
    assert e.anchor_tx is not None
    assert sent_hex == [e.anchor_tx.raw_hex]
    assert e.broadcast_result.ok
    assert e.broadcast_result.backend == "recording"
    assert e.broadcast_result.txid == "ee" * 32

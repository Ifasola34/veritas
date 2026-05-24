"""Bitcoin transaction broadcasters.

The oracle builds and signs an anchor tx in close_epoch(); a Broadcaster
optionally pushes that hex onto the actual Bitcoin network so the
commitment becomes provable on-chain rather than just locally serialized.

Two real implementations:
  - MempoolSpaceBroadcaster: HTTP POST to mempool.space/api/tx (per
    network: mainnet, testnet, signet). Zero local infrastructure.
  - BitcoindRpcBroadcaster: JSON-RPC sendrawtransaction against a local
    or remote bitcoind. Required when mempool.space is unreachable,
    rate-limited, or you don't want a third party seeing your tx hex
    before it's relayed.

Plus a NullBroadcaster (default) that does nothing — keeps existing
behavior (build but do not broadcast) intact when no broadcaster is
configured. Tests use FakeBroadcaster to inspect what would have been
sent without making network calls.

Env-driven configuration is the operator-facing API; see make_broadcaster().
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol


_NETWORKS = {
    "mainnet": "https://mempool.space/api/tx",
    "testnet": "https://mempool.space/testnet/api/tx",
    "signet": "https://mempool.space/signet/api/tx",
}


@dataclass(frozen=True)
class BroadcastResult:
    ok: bool
    txid: str | None
    error: str | None
    backend: str


class Broadcaster(Protocol):
    name: str

    def broadcast(self, raw_hex: str) -> BroadcastResult: ...


class NullBroadcaster:
    """Default: do nothing. Returns ok=True with no txid so callers that
    don't care about broadcasting still see a successful result.
    """

    name = "null"

    def broadcast(self, raw_hex: str) -> BroadcastResult:
        return BroadcastResult(ok=True, txid=None, error=None, backend=self.name)


class MempoolSpaceBroadcaster:
    """POST raw tx hex to mempool.space's /api/tx endpoint.

    On success, mempool.space returns the txid as plain text in the
    response body. On failure (rejected by node policy, malformed,
    already-in-mempool, etc.) it returns 400/422 with a short message.
    """

    def __init__(self, network: str = "signet", timeout_seconds: float = 15.0) -> None:
        if network not in _NETWORKS:
            raise ValueError(
                f"unsupported network {network!r}; one of {sorted(_NETWORKS)}"
            )
        self.network = network
        self.url = _NETWORKS[network]
        self.timeout = timeout_seconds
        self.name = f"mempool.space:{network}"

    def broadcast(self, raw_hex: str) -> BroadcastResult:
        req = urllib.request.Request(
            self.url,
            data=raw_hex.encode("ascii"),
            method="POST",
            headers={"Content-Type": "text/plain"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace").strip()
            return BroadcastResult(
                ok=True, txid=body, error=None, backend=self.name
            )
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace").strip()
            return BroadcastResult(
                ok=False, txid=None,
                error=f"HTTP {e.code}: {err}",
                backend=self.name,
            )
        except (urllib.error.URLError, TimeoutError) as e:
            return BroadcastResult(
                ok=False, txid=None,
                error=f"network error: {e}",
                backend=self.name,
            )


class BitcoindRpcBroadcaster:
    """JSON-RPC sendrawtransaction against a bitcoind node.

    rpc_url: full URL including credentials, e.g.
        http://rpcuser:rpcpass@127.0.0.1:18332
    or without credentials if rpc_auth=(user, pass) is supplied.
    """

    def __init__(
        self,
        rpc_url: str,
        rpc_auth: tuple[str, str] | None = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        self.rpc_url = rpc_url
        self.rpc_auth = rpc_auth
        self.timeout = timeout_seconds
        self.name = "bitcoind-rpc"

    def broadcast(self, raw_hex: str) -> BroadcastResult:
        body = json.dumps({
            "jsonrpc": "1.0",
            "id": "veritas",
            "method": "sendrawtransaction",
            "params": [raw_hex],
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.rpc_auth is not None:
            user, password = self.rpc_auth
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        req = urllib.request.Request(
            self.rpc_url, data=body, method="POST", headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace").strip()
            return BroadcastResult(
                ok=False, txid=None,
                error=f"HTTP {e.code}: {err}",
                backend=self.name,
            )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            return BroadcastResult(
                ok=False, txid=None,
                error=f"transport error: {e}",
                backend=self.name,
            )
        if data.get("error"):
            return BroadcastResult(
                ok=False, txid=None,
                error=f"rpc error: {data['error']}",
                backend=self.name,
            )
        return BroadcastResult(
            ok=True, txid=data.get("result"), error=None, backend=self.name,
        )


def make_broadcaster() -> Broadcaster:
    """Construct a broadcaster from environment.

    Disabled by default — returns NullBroadcaster unless
    VERITAS_ANCHOR_BROADCAST=1 is set. This prevents tests, dev runs,
    and misconfigured prod from accidentally pushing txs onto signet
    or mainnet.

    Env vars:
      VERITAS_ANCHOR_BROADCAST    "1" to enable; anything else = NullBroadcaster
      VERITAS_BROADCASTER         "mempool" (default) or "bitcoind"
      VERITAS_BTC_NETWORK         mainnet | testnet | signet (default signet)
      VERITAS_BTC_RPC_URL         required when VERITAS_BROADCASTER=bitcoind
      VERITAS_BTC_RPC_USER        optional basic-auth username for bitcoind
      VERITAS_BTC_RPC_PASS        optional basic-auth password for bitcoind
    """
    if os.environ.get("VERITAS_ANCHOR_BROADCAST") != "1":
        return NullBroadcaster()
    backend = os.environ.get("VERITAS_BROADCASTER", "mempool").lower()
    if backend == "mempool":
        network = os.environ.get("VERITAS_BTC_NETWORK", "signet")
        return MempoolSpaceBroadcaster(network=network)
    if backend == "bitcoind":
        url = os.environ.get("VERITAS_BTC_RPC_URL")
        if not url:
            raise RuntimeError(
                "VERITAS_BROADCASTER=bitcoind requires VERITAS_BTC_RPC_URL"
            )
        user = os.environ.get("VERITAS_BTC_RPC_USER")
        password = os.environ.get("VERITAS_BTC_RPC_PASS")
        auth = (user, password) if user and password else None
        return BitcoindRpcBroadcaster(rpc_url=url, rpc_auth=auth)
    raise RuntimeError(f"unsupported VERITAS_BROADCASTER: {backend!r}")

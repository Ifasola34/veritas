#!/usr/bin/env python3
"""Build AND broadcast a VERITAS anchor to Bitcoin signet (the free test network).

Run make_address.py first and fund the printed address. This signs an
attestation, folds it into a Merkle root, builds the OP_RETURN anchor tx
against your funded signet UTXO, broadcasts it to signet via mempool.space,
and prints the txid. Signet coins have no monetary value.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import urllib.request
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from veritas.crypto import OracleKey, derive_anchor_key  # noqa: E402
from veritas.anchor import Utxo, derive_anchor_pubkey, parse_op_return_payload  # noqa: E402
from veritas.oracle import Oracle, OracleConfig  # noqa: E402
from veritas.broadcast import NullBroadcaster, MempoolSpaceBroadcaster  # noqa: E402
from bech32 import encode_segwit  # noqa: E402

MEMPOOL = "https://mempool.space/signet/api"
TEXT = "VERITAS signet demo: verifiable AI attestation anchored to Bitcoin (free test network)"
MODEL = "veritas.sentiment.keyword.v1"


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _get(url):
    with urllib.request.urlopen(url, timeout=20) as r:
        return json.loads(r.read().decode())


def main():
    keyfile = os.path.join(HERE, "oracle.key")
    if not os.path.exists(keyfile):
        raise SystemExit("No oracle.key here yet. Run:  python make_address.py")
    key = OracleKey.from_hex(open(keyfile).read().strip())
    anchor_pub = derive_anchor_pubkey(derive_anchor_key(key))
    addr = encode_segwit("tb", 0, hash160(anchor_pub))

    utxos = _get(f"{MEMPOOL}/address/{addr}/utxo")
    if not utxos:
        raise SystemExit(f"No coins at {addr} yet. Fund it at https://signetfaucet.com first.")
    u = max(utxos, key=lambda x: x["value"])
    confirmed = u.get("status", {}).get("confirmed", False)
    utxo = Utxo(txid=u["txid"], vout=u["vout"], value_sats=u["value"], pubkey_compressed=anchor_pub)

    try:
        rate = max(int(_get(f"{MEMPOOL}/v1/fees/recommended").get("fastestFee", 1)), 2)
    except Exception:
        rate = 2
    fee_sats = max(rate * 180, 300)

    out = Path(HERE) / "artifacts"
    data_dir = out / "veritas-data"
    if data_dir.exists():
        shutil.rmtree(data_dir)
    out.mkdir(parents=True, exist_ok=True)

    oracle = Oracle(key, OracleConfig(
        data_dir=data_dir, anchor_utxo=utxo, fee_sats=fee_sats, broadcaster=NullBroadcaster()))
    signed, evt = oracle.attest(MODEL, TEXT)
    epoch = oracle.close_epoch()
    proof = oracle.inclusion_proof(epoch.number, 0)
    anchor = epoch.anchor_tx
    cp = epoch.checkpoint_event
    decoded = parse_op_return_payload(anchor.op_return_payload)
    change = utxo.value_sats - anchor.fee_sats

    print("=" * 70)
    print("VERITAS signet anchor")
    print(f"  funding address : {addr}")
    print(f"  attested text   : {TEXT!r}")
    print(f"  input_hash      : {signed.attestation.input_hash}")
    print(f"  oracle pubkey   : {key.xonly_pubkey_hex}")
    print(f"  merkle root     : {epoch.root_hex}  (leaves: {decoded['leaf_count']})")
    print(f"  funding UTXO    : {utxo.txid}:{utxo.vout} ({utxo.value_sats} sats, confirmed={confirmed})")
    print(f"  fee             : {anchor.fee_sats} sats, change {change} sats")
    print(f"  anchor txid     : {anchor.txid}")
    print("=" * 70)
    if change < 0:
        raise SystemExit(f"UTXO too small ({utxo.value_sats} sats) for the fee. Get a bigger faucet drip.")

    print("Broadcasting to signet via mempool.space ...")
    res = MempoolSpaceBroadcaster(network="signet").broadcast(anchor.raw_hex)
    print(f"  ok={res.ok} txid={res.txid} error={res.error}")

    bundle = {
        "signedAttestation": json.loads(signed.to_json()),
        "nostrEvent": evt.to_dict(),
        "merkleProof": {
            "leaf_hex": proof.leaf.hex(),
            "siblings_hex": [s.hex() for s in proof.siblings],
            "directions": list(proof.directions),
            "root_hex": proof.root.hex(),
            "size": proof.size,
            "index": proof.index,
        },
        "checkpointEvent": cp.to_dict(),
        "anchorRawTxHex": anchor.raw_hex,
        "_meta": {
            "network": "signet",
            "anchor_txid": anchor.txid,
            "oracle_pubkey": key.xonly_pubkey_hex,
            "input_text": TEXT,
            "input_hash": signed.attestation.input_hash,
            "model": MODEL,
            "model_output": signed.attestation.output,
            "broadcast_ok": res.ok,
            "broadcast_error": res.error,
            "op_return": {
                "epoch": decoded["epoch"],
                "leaf_count": decoded["leaf_count"],
                "merkle_root": decoded["merkle_root"].hex(),
                "payload_hex": anchor.op_return_payload.hex(),
            },
        },
    }
    (out / "bundle.json").write_text(json.dumps(bundle, indent=2))
    print(f"\nSaved bundle -> {out / 'bundle.json'}")
    if res.ok:
        print(f"Look it up: https://mempool.space/signet/tx/{anchor.txid}")


if __name__ == "__main__":
    main()

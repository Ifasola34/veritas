#!/usr/bin/env python3
"""Sweep all BTC at your VERITAS funding address back to your own wallet.

After you anchor, the change (everything except the fee) lands back at the
bc1q... address derived from oracle.key. This sends it to an address you
choose. It BUILDS + REVIEWS by default and broadcasts only after you type
'yes' (or pass --yes). The destination can be native segwit (bc1q...) or a
legacy (1.../3...) address.

    python sweep.py <your-wallet-address> [--rate SAT_PER_VB] [--yes]

The signing core is identical to the anchor's: a single BIP-143 P2WPKH input
signed with the anchor key derived from oracle.key.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from coincurve import PrivateKey  # noqa: E402
from veritas.crypto import OracleKey, derive_anchor_key  # noqa: E402
from veritas.anchor import derive_anchor_pubkey  # noqa: E402
from bech32 import (  # noqa: E402
    CHARSET, bech32_polymod, bech32_hrp_expand, convertbits, encode_segwit,
)

MEMPOOL = "https://mempool.space/api"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _get(u):
    with urllib.request.urlopen(u, timeout=20) as r:
        return json.loads(r.read().decode())


def _post(u, data):
    req = urllib.request.Request(u, data=data.encode("ascii"), method="POST",
                                 headers={"Content-Type": "text/plain"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode().strip()


def varint(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def h160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def b58check_decode(s):
    n = 0
    for c in s:
        if c not in B58:
            raise ValueError("not a valid base58 address")
        n = n * 58 + B58.index(c)
    full = n.to_bytes((n.bit_length() + 7) // 8, "big")
    full = b"\x00" * (len(s) - len(s.lstrip("1"))) + full
    payload, chk = full[:-4], full[-4:]
    if sha256d(payload)[:4] != chk:
        raise ValueError("bad base58 checksum -- address is mistyped")
    return payload


def bech32_decode(addr):
    """Verify a bech32 (segwit v0) address and return (hrp, data) or (None, None)."""
    if any(ord(c) < 33 or ord(c) > 126 for c in addr):
        return None, None
    if addr.lower() != addr and addr.upper() != addr:
        return None, None  # mixed case is invalid
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return None, None
    if not all(c in CHARSET for c in addr[pos + 1:]):
        return None, None
    hrp = addr[:pos]
    data = [CHARSET.find(c) for c in addr[pos + 1:]]
    if bech32_polymod(bech32_hrp_expand(hrp) + data) != 1:
        return None, None  # bad checksum (or a bech32m/Taproot address)
    return hrp, data[:-6]


def dest_spk(addr):
    """Return (scriptPubKey, human_kind) for a mainnet destination address.

    Raises ValueError on anything it can't validate -- a mistyped address won't
    pass its checksum, so funds can't be sent into the void.
    """
    if addr.lower().startswith("bc1"):
        hrp, data = bech32_decode(addr)
        if hrp != "bc" or not data:
            raise ValueError("could not validate this bc1 address (if it's Taproot/bc1p, "
                             "use a bc1q or a legacy 1.../3... address instead)")
        witver = data[0]
        prog = convertbits(data[1:], 5, 8, False)
        if witver != 0 or prog is None or len(prog) not in (20, 32):
            raise ValueError("unsupported bc1 address -- use a standard bc1q address")
        prog = bytes(prog)
        return b"\x00" + bytes([len(prog)]) + prog, ("P2WPKH (bc1q)" if len(prog) == 20 else "P2WSH (bc1q)")
    p = b58check_decode(addr)
    ver, hsh = p[0], p[1:]
    if len(hsh) != 20:
        raise ValueError("unexpected address hash length")
    if ver == 0x00:
        return b"\x76\xa9\x14" + hsh + b"\x88\xac", "P2PKH (legacy 1...)"
    if ver == 0x05:
        return b"\xa9\x14" + hsh + b"\x87", "P2SH (3...)"
    raise ValueError(f"unsupported address version byte {ver:#x}")


# Tell-tale fragments of the example placeholder, so a copy-pasted
# "bc1q-your-wallet-address" gets a friendly nudge instead of a scary traceback.
_PLACEHOLDERS = (
    "your-wallet", "your_wallet", "yourwallet",
    "your-address", "your_address", "youraddress",
    "your-actual", "your_actual", "youractual",
    "your-receive", "yourreceive", "example", "placeholder",
)


def looks_like_placeholder(addr):
    """True if the user pasted an example placeholder instead of a real address."""
    a = addr.strip().lower()
    return a.startswith("<") or a.endswith(">") or any(h in a for h in _PLACEHOLDERS)


def main():
    ap = argparse.ArgumentParser(description="Sweep your VERITAS funding address back to your wallet.")
    ap.add_argument("dest", help="your wallet address to receive the BTC (bc1q... or 1.../3...)")
    ap.add_argument("--rate", type=int, default=2, help="fee rate in sat/vB (default 2)")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt and broadcast")
    args = ap.parse_args()

    keyfile = os.path.join(HERE, "oracle.key")
    if not os.path.exists(keyfile):
        raise SystemExit("No oracle.key here. Run make_address.py first.")
    key = OracleKey.from_hex(open(keyfile).read().strip())
    anchor_priv = derive_anchor_key(key)
    anchor_pub = derive_anchor_pubkey(anchor_priv)
    src = encode_segwit("bc", 0, h160(anchor_pub))

    if looks_like_placeholder(args.dest):
        raise SystemExit(
            "That looks like the example placeholder, not a real address.\n"
            f"  you passed: {args.dest}\n"
            "Replace it with YOUR OWN wallet's receive address -- a native segwit\n"
            "(bc1q...) or legacy (1.../3...) address, NOT a Taproot (bc1p...) one.")
    try:
        spk, kind = dest_spk(args.dest)  # validates early -- a typo can't send funds into the void
    except ValueError as e:
        raise SystemExit(f"That destination address didn't validate: {e}")

    utxos = [c for c in _get(f"{MEMPOOL}/address/{src}/utxo") if c.get("status", {}).get("confirmed")]
    if not utxos:
        raise SystemExit(f"No confirmed BTC at {src} to sweep.")
    u = max(utxos, key=lambda x: x["value"])
    value, txid, vout = u["value"], u["txid"], u["vout"]
    if len(utxos) > 1:
        print(f"Note: {len(utxos)} confirmed UTXOs here; sweeping the largest "
              f"({value} sats). Re-run to sweep the rest.")

    vsize = 110  # 1-in / 1-out P2WPKH spend
    fee = max(vsize * args.rate, 150)
    send = value - fee
    if send <= 0:
        raise SystemExit(f"UTXO ({value} sats) is too small to cover the fee ({fee} sats).")

    # BIP-143 sighash for a single native-segwit (P2WPKH) input.
    prevout = bytes.fromhex(txid)[::-1] + vout.to_bytes(4, "little")
    seq = b"\xff\xff\xff\xff"
    out = send.to_bytes(8, "little") + varint(len(spk)) + spk
    version = (2).to_bytes(4, "little")
    locktime = (0).to_bytes(4, "little")
    hp = sha256d(prevout)
    hs = sha256d(seq)
    ho = sha256d(out)
    pkh = h160(anchor_pub)
    scriptcode = b"\x76\xa9\x14" + pkh + b"\x88\xac"
    preimage = (version + hp + hs + prevout + varint(len(scriptcode)) + scriptcode
                + value.to_bytes(8, "little") + seq + ho + locktime + (1).to_bytes(4, "little"))
    sighash = sha256d(preimage)
    der = PrivateKey(anchor_priv).sign(sighash, hasher=None) + b"\x01"
    witness = bytes([2]) + varint(len(der)) + der + varint(len(anchor_pub)) + anchor_pub
    raw = (version + b"\x00\x01" + varint(1) + prevout + b"\x00" + seq
           + varint(1) + out + witness + locktime)
    nonwit = (version + varint(1) + prevout + b"\x00" + seq + varint(1) + out + locktime)
    new_txid = sha256d(nonwit)[::-1].hex()

    try:
        usd = _get(f"{MEMPOOL}/v1/prices")["USD"]
        send_usd, fee_usd = f"${send * usd / 1e8:.2f}", f"${fee * usd / 1e8:.2f}"
    except Exception:
        send_usd = fee_usd = "n/a"

    print("=" * 66)
    print("VERITAS sweep   ==>  sends REAL BTC to your wallet")
    print("=" * 66)
    print(f"From        : {src}")
    print(f"  UTXO      : {txid}:{vout}  ({value} sats, confirmed)")
    print(f"To          : {args.dest}  [{kind}]")
    print(f"Fee         : {fee} sats (~{args.rate} sat/vB) = {fee_usd}")
    print(f"You receive : {send} sats = {send_usd}")
    print(f"TXID        : {new_txid}")
    print("=" * 66)

    if not args.yes:
        if input("Type 'yes' to broadcast and send this to your wallet: ").strip().lower() != "yes":
            raise SystemExit("Aborted -- nothing broadcast.")

    print("\nBroadcasting to Bitcoin mainnet ...")
    print("network txid:", _post(f"{MEMPOOL}/tx", raw.hex()))


if __name__ == "__main__":
    main()

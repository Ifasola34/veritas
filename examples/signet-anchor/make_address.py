"""Generate a fresh VERITAS oracle key and print its signet funding address.

Run this first. It creates oracle.key (mode 0600) in this folder and prints a
tb1q... signet address that is uniquely yours. Fund that address at a signet
faucet, then run anchor.py. Nothing is broadcast here; this is offline + local.
"""
from __future__ import annotations

import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from veritas.crypto import OracleKey, derive_anchor_key  # noqa: E402
from veritas.anchor import derive_anchor_pubkey  # noqa: E402
from bech32 import encode_segwit  # noqa: E402


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


keyfile = os.path.join(HERE, "oracle.key")
if os.path.exists(keyfile):
    key = OracleKey.from_hex(open(keyfile).read().strip())
    print(f"oracle.key already exists, reusing it ({keyfile})")
else:
    key = OracleKey.generate()
    fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (key.privkey.hex() + "\n").encode("ascii"))
    finally:
        os.close(fd)
    print(f"Generated a fresh VERITAS oracle key -> {keyfile} (mode 0600)")

anchor_pub = derive_anchor_pubkey(derive_anchor_key(key))
addr = encode_segwit("tb", 0, hash160(anchor_pub))  # "tb" = signet/testnet P2WPKH

print()
print("Oracle pubkey (your identity):", key.xonly_pubkey_hex)
print()
print("  SIGNET FUNDING ADDRESS:  " + addr)
print()
print("Next: fund that tb1q... address at https://signetfaucet.com , then run:")
print("  python anchor.py")

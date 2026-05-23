"""Cryptographic primitives.

We use libsecp256k1 via the `coincurve` binding for the heavy lifting
(scalar multiplication on secp256k1), and implement the surrounding
serialization and tagged-hash logic ourselves so the protocol is fully
spelled out in the code rather than hidden behind a library helper.

Schnorr signatures here are BIP-340 compatible — meaning the exact same
signature format Bitcoin Taproot, Nostr, and DLC oracles all consume.
That is intentional: one oracle key, used unmodified, for all three.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass

from coincurve import PrivateKey, PublicKey
from coincurve.keys import PublicKeyXOnly


# secp256k1 group order (n). BIP-340 requires private scalars in [1, n-1].
SECP256K1_ORDER = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    """Bitcoin-style double SHA-256."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """BIP-340 tagged hash.

        H_tag(x) := SHA256(SHA256(tag) || SHA256(tag) || x)

    This provides domain separation so that signatures or commitments under
    different protocols can never be confused for one another.
    """
    tag_hash = sha256(tag.encode("utf-8"))
    return sha256(tag_hash + tag_hash + msg)


@dataclass(frozen=True)
class OracleKey:
    """A BIP-340 / Nostr-compatible oracle keypair.

    Internally stored as the 32-byte private scalar. The x-only public key
    is what Nostr exposes and what we use as the oracle's stable identity.
    """

    privkey: bytes  # 32 bytes

    def __post_init__(self) -> None:
        if len(self.privkey) != 32:
            raise ValueError("privkey must be exactly 32 bytes")
        scalar = int.from_bytes(self.privkey, "big")
        if not (1 <= scalar < SECP256K1_ORDER):
            raise ValueError("privkey out of valid scalar range")

    @classmethod
    def generate(cls) -> "OracleKey":
        # 32 bytes from os.urandom, rejection-sampled to be < group order.
        while True:
            cand = secrets.token_bytes(32)
            scalar = int.from_bytes(cand, "big")
            if 1 <= scalar < SECP256K1_ORDER:
                return cls(cand)

    @classmethod
    def from_hex(cls, hexstr: str) -> "OracleKey":
        return cls(bytes.fromhex(hexstr))

    @property
    def xonly_pubkey(self) -> bytes:
        """32-byte x-only pubkey (BIP-340 / Nostr canonical form)."""
        pk = PrivateKey(self.privkey).public_key
        compressed = pk.format(compressed=True)  # 33 bytes: prefix||x
        return compressed[1:]

    @property
    def xonly_pubkey_hex(self) -> str:
        return self.xonly_pubkey.hex()

    @property
    def npub_bytes(self) -> bytes:
        # Nostr "npub" is bech32(xonly_pubkey); we keep raw bytes here.
        return self.xonly_pubkey


def schnorr_sign(msg32: bytes, key: OracleKey, aux_rand: bytes | None = None) -> bytes:
    """BIP-340 Schnorr signature.

    msg32 must be exactly 32 bytes (e.g. the output of `tagged_hash` or
    an event ID). Returns 64 bytes.
    """
    if len(msg32) != 32:
        raise ValueError("BIP-340 signs a 32-byte message digest")
    if aux_rand is None:
        aux_rand = os.urandom(32)
    if len(aux_rand) != 32:
        raise ValueError("aux_rand must be 32 bytes")
    pk = PrivateKey(key.privkey)
    return pk.sign_schnorr(msg32, aux_rand)


def schnorr_verify(msg32: bytes, sig64: bytes, xonly_pubkey: bytes) -> bool:
    """BIP-340 Schnorr verify. Pure boolean — no exceptions on bad sig."""
    if len(msg32) != 32 or len(sig64) != 64 or len(xonly_pubkey) != 32:
        return False
    try:
        pk = PublicKeyXOnly(xonly_pubkey)
        return pk.verify(sig64, msg32)
    except Exception:
        return False


def derive_anchor_key(oracle_key: OracleKey) -> bytes:
    """Deterministically derive a separate 32-byte secret for anchor-tx signing.

    We don't want to use the oracle's attestation key to sign Bitcoin
    transactions — losing one shouldn't lose the other. This derivation is
    a tagged-hash subkey from the oracle key.
    """
    return tagged_hash("VRT1/anchor-key", oracle_key.privkey)

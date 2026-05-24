"""Bitcoin anchor transaction.

We commit a Merkle root to Bitcoin via OP_RETURN. The transaction structure
is a single P2WPKH input -> P2WPKH change output + OP_RETURN data output.

This module builds a *valid* segwit transaction structure and signs it
using BIP-143 sighash. For the prototype we don't broadcast — we serialize
to hex. A real deployment would replace `broadcast()` with a call to a
Bitcoin node, BlockCypher, mempool.space's POST endpoint, or similar.

Why this matters: the most common pattern in shoddy "Bitcoin-anchored"
projects is to *describe* the anchor and never actually serialize a tx.
The fact that we serialize a real, valid tx (one that a `bitcoind -signet`
would accept once funded) is what makes the anchor real.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from coincurve import PrivateKey

from . import PROTOCOL_TAG


OP_RETURN_VERSION = 1


# ---------- low-level encoding helpers ----------

def _varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xFD" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xFE" + n.to_bytes(4, "little")
    return b"\xFF" + n.to_bytes(8, "little")


def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# ---------- public types ----------

@dataclass(frozen=True)
class Utxo:
    txid: str          # 64-char hex, little-endian-displayed-as-big
    vout: int
    value_sats: int
    pubkey_compressed: bytes   # 33 bytes


@dataclass(frozen=True)
class AnchorTx:
    txid: str
    raw_hex: str
    op_return_payload: bytes
    fee_sats: int


# ---------- builder ----------

def build_op_return_payload(
    merkle_root: bytes, epoch: int, leaf_count: int
) -> bytes:
    """Serialize the OP_RETURN data.

    Layout (49 bytes, fits in a single direct-push OP_RETURN):
      tag(4) || version(1) || epoch(8 BE) || leaf_count(4 BE) || root(32)

    Committing leaf_count on-chain lets verifiers reject Merkle proofs
    whose claimed tree size disagrees with what the oracle anchored.
    """
    if len(merkle_root) != 32:
        raise ValueError("merkle_root must be 32 bytes")
    if not 0 <= leaf_count < 2**32:
        raise ValueError("leaf_count out of range")
    if not 0 <= epoch < 2**64:
        raise ValueError("epoch out of range")
    return (
        PROTOCOL_TAG.encode("ascii")
        + bytes([OP_RETURN_VERSION])
        + epoch.to_bytes(8, "big")
        + leaf_count.to_bytes(4, "big")
        + merkle_root
    )


def parse_op_return_payload(payload: bytes) -> dict:
    """Inverse of build_op_return_payload. Raises ValueError on malformed input."""
    if len(payload) != 49:
        raise ValueError(f"OP_RETURN payload wrong length: {len(payload)} != 49")
    tag = payload[:4]
    if tag != PROTOCOL_TAG.encode("ascii"):
        raise ValueError(f"unknown protocol tag: {tag!r}")
    version = payload[4]
    if version != OP_RETURN_VERSION:
        raise ValueError(f"unsupported OP_RETURN version: {version}")
    epoch = int.from_bytes(payload[5:13], "big")
    leaf_count = int.from_bytes(payload[13:17], "big")
    merkle_root = payload[17:49]
    return {
        "tag": tag.decode("ascii"),
        "version": version,
        "epoch": epoch,
        "leaf_count": leaf_count,
        "merkle_root": merkle_root,
    }


def derive_anchor_pubkey(privkey: bytes) -> bytes:
    """Compressed (33-byte) secp256k1 pubkey for an anchor private key."""
    if len(privkey) != 32:
        raise ValueError("privkey must be 32 bytes")
    return PrivateKey(privkey).public_key.format(compressed=True)


# Sanity caps. Real Bitcoin txs are bounded by consensus (MAX_BLOCK_WEIGHT ~4M
# weight units); these caps are loose enough to never reject a real tx but
# tight enough to short-circuit adversarial inputs before they consume CPU.
_MAX_INS = 10_000
_MAX_OUTS = 10_000
_MAX_SCRIPT_LEN = 100_000


def extract_op_return_from_raw_tx(raw_hex: str) -> bytes | None:
    """Walk a serialized (segwit or legacy) tx and return the OP_RETURN data
    payload (without the OP_RETURN/push opcodes), or None if no OP_RETURN
    output is present. Used by verifiers cross-checking checkpoint roots
    against the on-chain anchor.

    Raises ValueError on malformed or out-of-bounds hex. Caller-supplied
    raw_hex is treated as untrusted: every read is bounds-checked, varint
    counts are capped, and scripts longer than 100KB are rejected so an
    adversarial tx cannot DoS the verifier.
    """
    try:
        tx = bytes.fromhex(raw_hex)
    except ValueError as e:
        raise ValueError(f"raw_hex is not valid hex: {e}")
    n = len(tx)

    def _need(pos: int, want: int) -> None:
        if pos + want > n:
            raise ValueError(
                f"truncated tx: need {want} bytes at offset {pos}, have {n - pos}"
            )

    def _read_varint(pos: int) -> tuple[int, int]:
        _need(pos, 1)
        first = tx[pos]
        if first < 0xFD:
            return first, pos + 1
        if first == 0xFD:
            _need(pos + 1, 2)
            return int.from_bytes(tx[pos + 1:pos + 3], "little"), pos + 3
        if first == 0xFE:
            _need(pos + 1, 4)
            return int.from_bytes(tx[pos + 1:pos + 5], "little"), pos + 5
        _need(pos + 1, 8)
        return int.from_bytes(tx[pos + 1:pos + 9], "little"), pos + 9

    _need(0, 4)
    cursor = 4  # skip version
    # Detect segwit marker+flag.
    if n >= cursor + 2 and tx[cursor] == 0x00 and tx[cursor + 1] == 0x01:
        cursor += 2

    n_in, cursor = _read_varint(cursor)
    if n_in > _MAX_INS:
        raise ValueError(f"input count {n_in} exceeds cap {_MAX_INS}")
    for _ in range(n_in):
        _need(cursor, 36)
        cursor += 36  # outpoint
        slen, cursor = _read_varint(cursor)
        if slen > _MAX_SCRIPT_LEN:
            raise ValueError(f"scriptSig length {slen} exceeds cap")
        _need(cursor, slen + 4)
        cursor += slen + 4  # scriptSig + sequence

    n_out, cursor = _read_varint(cursor)
    if n_out > _MAX_OUTS:
        raise ValueError(f"output count {n_out} exceeds cap {_MAX_OUTS}")
    for _ in range(n_out):
        _need(cursor, 8)
        cursor += 8  # value
        slen, cursor = _read_varint(cursor)
        if slen > _MAX_SCRIPT_LEN:
            raise ValueError(f"scriptPubKey length {slen} exceeds cap")
        _need(cursor, slen)
        script = tx[cursor:cursor + slen]
        cursor += slen
        if script and script[0] == 0x6A:  # OP_RETURN
            if len(script) < 2:
                continue
            push = script[1]
            if 1 <= push <= 0x4B and len(script) == 2 + push:
                return script[2:]
            if (
                push == 0x4C
                and len(script) >= 3
                and len(script) == 3 + script[2]
            ):
                return script[3:]
    return None


def _p2wpkh_script(pubkey_compressed: bytes) -> bytes:
    """P2WPKH scriptPubKey: OP_0 <20-byte-hash160>."""
    h160 = _hash160(pubkey_compressed)
    return b"\x00\x14" + h160


def _op_return_script(payload: bytes) -> bytes:
    """OP_RETURN <push>."""
    if len(payload) > 80:
        raise ValueError(f"OP_RETURN payload too big: {len(payload)} > 80")
    if len(payload) < 76:
        return b"\x6a" + bytes([len(payload)]) + payload
    return b"\x6a\x4c" + bytes([len(payload)]) + payload  # OP_PUSHDATA1


def build_anchor_tx(
    *,
    utxo: Utxo,
    privkey: bytes,
    merkle_root: bytes,
    epoch: int,
    leaf_count: int,
    fee_sats: int = 500,
    change_pubkey_compressed: bytes | None = None,
) -> AnchorTx:
    """Build & sign a P2WPKH -> P2WPKH+OP_RETURN tx.

    Caller is responsible for ensuring `utxo.value_sats >= fee_sats`.
    The output of the OP_RETURN is 0 sats (data carrier).

    The UTXO's pubkey MUST match the supplied privkey — otherwise the
    witness signature will not satisfy the input's scriptPubKey and the
    tx will be rejected by every node. We enforce this rather than build
    a silently-invalid tx.

    Returns the serialized transaction and its txid. NOT broadcast.
    """
    if len(privkey) != 32:
        raise ValueError("privkey must be 32 bytes")
    derived_pk = derive_anchor_pubkey(privkey)
    if utxo.pubkey_compressed != derived_pk:
        raise ValueError(
            "utxo.pubkey_compressed does not match the privkey; "
            "anchor would build an unspendable transaction"
        )
    if change_pubkey_compressed is None:
        change_pubkey_compressed = utxo.pubkey_compressed

    payload = build_op_return_payload(merkle_root, epoch, leaf_count)
    op_return_spk = _op_return_script(payload)
    change_value = utxo.value_sats - fee_sats
    if change_value < 0:
        raise ValueError("fee exceeds input value")
    change_spk = _p2wpkh_script(change_pubkey_compressed)

    # Inputs
    txid_bytes = bytes.fromhex(utxo.txid)[::-1]  # internal byte order
    prev_outpoint = txid_bytes + utxo.vout.to_bytes(4, "little")
    sequence = b"\xFF\xFF\xFF\xFF"

    # Outputs:  out0 = OP_RETURN (0 sats), out1 = change P2WPKH
    out0 = (0).to_bytes(8, "little") + _varint(len(op_return_spk)) + op_return_spk
    out1 = (
        change_value.to_bytes(8, "little")
        + _varint(len(change_spk))
        + change_spk
    )

    version = (2).to_bytes(4, "little")
    locktime = (0).to_bytes(4, "little")

    # BIP-143 sighash for segwit (single input, ALL).
    hash_prevouts = _sha256d(prev_outpoint)
    hash_sequence = _sha256d(sequence)
    hash_outputs = _sha256d(out0 + out1)

    # scriptCode for P2WPKH is the equivalent P2PKH:
    #   OP_DUP OP_HASH160 <h160> OP_EQUALVERIFY OP_CHECKSIG
    pk_h160 = _hash160(utxo.pubkey_compressed)
    script_code = b"\x76\xa9\x14" + pk_h160 + b"\x88\xac"
    script_code_len = _varint(len(script_code))

    sighash_preimage = (
        version
        + hash_prevouts
        + hash_sequence
        + prev_outpoint
        + script_code_len
        + script_code
        + utxo.value_sats.to_bytes(8, "little")
        + sequence
        + hash_outputs
        + locktime
        + (1).to_bytes(4, "little")   # SIGHASH_ALL
    )
    sighash = _sha256d(sighash_preimage)

    pk = PrivateKey(privkey)
    der_sig = pk.sign(sighash, hasher=None)  # ECDSA, low-s, DER, over our digest
    der_sig_with_hashtype = der_sig + b"\x01"  # SIGHASH_ALL

    # Witness: 02 <sig> <pubkey>
    witness_items = [der_sig_with_hashtype, utxo.pubkey_compressed]
    witness = bytes([len(witness_items)]) + b"".join(
        _varint(len(w)) + w for w in witness_items
    )

    # Serialized segwit transaction (BIP-141):
    #   version(4) || 0x00 0x01 || ins || outs || witness || locktime(4)
    tx_with_witness = (
        version
        + b"\x00\x01"
        + _varint(1)
        + prev_outpoint + b"\x00" + sequence  # empty scriptSig
        + _varint(2)
        + out0 + out1
        + witness
        + locktime
    )

    # txid is sha256d of the *non-witness* serialization (BIP-141).
    tx_without_witness = (
        version
        + _varint(1)
        + prev_outpoint + b"\x00" + sequence
        + _varint(2)
        + out0 + out1
        + locktime
    )
    txid = _sha256d(tx_without_witness)[::-1].hex()

    return AnchorTx(
        txid=txid,
        raw_hex=tx_with_witness.hex(),
        op_return_payload=payload,
        fee_sats=fee_sats,
    )

"""Minimal BIP-173 bech32 segwit-v0 address encoder.

Used ONLY to render the P2WPKH funding address (bc1q...) for the anchor
key. The on-chain transaction itself uses the raw scriptPubKey built in
veritas.anchor; this module never touches consensus logic. Encoder is the
BIP-173 reference implementation; __main__ asserts the official mainnet
P2WPKH test vector before we trust any address with real funds.
"""
from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values: list[int]) -> int:
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: list[int]) -> str:
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def convertbits(data, frombits: int, tobits: int, pad: bool = True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def encode_segwit(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode a segwit address. witver 0 (P2WPKH/P2WSH) uses bech32."""
    five_bit = convertbits(list(witprog), 8, 5)
    if five_bit is None:
        raise ValueError("convertbits failed")
    return bech32_encode(hrp, [witver] + five_bit)


if __name__ == "__main__":
    # BIP-173 official mainnet P2WPKH test vector.
    prog = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    got = encode_segwit("bc", 0, prog)
    exp = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert got == exp, f"BECH32 SELFTEST FAILED: {got} != {exp}"
    print("BECH32 SELFTEST OK:", got)

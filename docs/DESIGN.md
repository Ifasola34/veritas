# VERITAS — Technical Design

**Verifiable, Economically-Recoverable, Inference-Time Attestation System.**

A Bitcoin-anchored oracle that signs, publishes, prices, and proves AI inference outputs.

---

## One-paragraph summary

VERITAS turns every AI inference into a cryptographically verifiable object. The oracle node runs a registered model, signs each `(model_id, input_hash, output, timestamp)` tuple with a BIP-340 Schnorr key, batches signatures into a Merkle tree, anchors the root to Bitcoin via OP_RETURN once per epoch, publishes individual attestations as NIP-01 Nostr events, and gates premium streams behind L402-style Lightning payments. Subscribers verify three things independently: (a) the Schnorr signature, (b) Merkle inclusion in the anchored root, (c) the anchor transaction on Bitcoin. Trust collapses from "trust the API provider" to "trust math and Bitcoin."

---

## System diagram

```
                ┌─────────────────────────────────┐
                │     Model registry (signed)     │
                │   model_id → weights_hash       │
                └────────────┬────────────────────┘
                             │
                             ▼
   ┌──────────────────────────────────────────────────┐
   │              ORACLE DAEMON                       │
   │  ┌────────────────────────────────────────────┐  │
   │  │  Inference loop                            │  │
   │  │    ↓                                       │  │
   │  │  Attestation = sign_schnorr(SHA256(        │  │
   │  │     model_id ‖ input_hash ‖ output         │  │
   │  │     ‖ timestamp ‖ epoch ))                 │  │
   │  └────────────────────────────────────────────┘  │
   │       │                                          │
   │       ├──────────── Nostr event (NIP-01) ───────┼──▶ relays
   │       │             kind=30078                   │
   │       │                                          │
   │       ├──────────── Merkle leaf ─────────────────┤
   │       │                                          │
   │       └──────────── L402 paywall (HTTP) ─────────┼──▶ subscribers
   │                                                  │
   └──────────────────┬───────────────────────────────┘
                      │ epoch_close
                      ▼
              ┌────────────────────┐
              │  Merkle root R     │
              └──────┬─────────────┘
                     │
                     ▼
            OP_RETURN("VRT1"||R||epoch)
                     │
                     ▼
            ┌────────────────────┐
            │  Bitcoin signet/   │
            │  mainnet anchor    │
            └────────────────────┘

                                    Verifier (anyone):
                                    1. fetch attestation from Nostr
                                    2. verify Schnorr sig
                                    3. fetch Merkle path from oracle
                                    4. recompute root, match anchor tx
                                    5. (optional) check anchor depth
```

---

## Attestation object

A VERITAS attestation is a deterministic, canonicalized payload:

```
Attestation := {
    "v":        1,                            # version
    "model":    "<model_id>",                 # e.g. "veritas.sentiment.v1"
    "input":    "<32-byte hex>",              # SHA-256 of normalized input
    "output":   <arbitrary JSON>,             # the inference result
    "ts":       <unix seconds>,
    "epoch":    <integer>,                    # which Merkle batch
    "oracle":   "<32-byte x-only pubkey hex>" # BIP-340 pubkey
}
```

The **attestation digest** is `tagged_hash("VRT1/attestation", canonical_json(Attestation))`.
The **signature** is BIP-340 Schnorr over that digest under the oracle's key.

A VERITAS event published to Nostr is just a NIP-01 event with:
- `kind = 30078` (parameterized replaceable per NIP-33, scoped per epoch)
- `tags = [["d", "<epoch>:<attestation_index>"], ["model", model_id], ["v", "VRT1"]]`
- `content = base64(canonical_json(Attestation))`
- `sig = bip340(eventid, oracle_priv)`

This way *the Nostr signature itself* is the attestation signature — we don't need a redundant signing layer. The oracle's Nostr pubkey **is** the oracle identity.

---

## Merkle batching

Per-epoch (default 600 seconds), the oracle:
1. Collects all attestation digests issued in the epoch.
2. Builds a Bitcoin-style double-SHA-256 Merkle tree (odd-leaf duplication).
3. Computes root `R`.
4. Persists `(epoch, R, leaves, paths)` to local store.
5. Broadcasts an anchor transaction with `OP_RETURN "VRT1" || R[0:28]` (32 bytes total — fits in 80-byte limit easily).
6. Publishes a "checkpoint" Nostr event (kind 30079) with `{epoch, root, anchor_txid}`.

Anchor transactions are real Bitcoin transactions. In this prototype, the anchor module emits **signet** by default and prints the raw hex for review; mainnet is gated behind an explicit flag and an external broadcast URL.

---

## Verifier flow

```
fetch attestation A (from Nostr or HTTP) →
    verify_schnorr(A.sig, A.eventid, A.oracle) →
        fetch checkpoint C for A.epoch →
            verify_schnorr(C.sig, C.eventid, A.oracle) →
                fetch inclusion proof π for A in C.root →
                    verify_merkle(A.digest, π, C.root) →
                        (optional) check anchor_txid in Bitcoin →
                            ✓ trustworthy attestation
```

Each step is independent and verifiable by any party. The oracle could lie or vanish; old attestations are still verifiable as long as the Bitcoin chain holds and one honest party retained the inclusion paths.

---

## Why these primitives, in this combination

| Component         | Why this and not the alternative                                                                 |
|-------------------|---------------------------------------------------------------------------------------------------|
| BIP-340 Schnorr   | Same curve & sig as Nostr and DLC oracles → one keypair, three uses (sign, publish, attest).      |
| Nostr             | Decentralized publication without rolling our own gossip; censorship cost > zero.                 |
| Merkle + OP_RETURN| Anchors thousands of attestations for the cost of one tx; verifiable by anyone with the chain.    |
| L402              | Lightning-native paywall, no accounts, no API keys, atomic per-call settlement.                   |
| Tagged hashes     | Domain separation prevents cross-protocol sig reuse — same hygiene as Taproot.                    |
| Replaceable Nostr | Premium feeds can be "latest only" without rewriting every event.                                 |

---

## Threat model (brief)

| Adversary             | Capability we prevent                                                                  | Capability we don't                       |
|-----------------------|----------------------------------------------------------------------------------------|-------------------------------------------|
| Malicious oracle      | Cannot retroactively alter an attestation; cannot omit one already in a published root | Can refuse to serve premium subscribers   |
| Nostr relay           | Cannot forge attestations (no oracle priv key)                                         | Can drop / censor; client must use ≥2     |
| Network observer      | Cannot link payment to identity beyond Lightning's privacy                             | Can see Bitcoin anchor txs (intentional)  |
| Bitcoin reorg < 6     | We treat anchors with fewer than 6 confirmations as "pending"                          | Deep reorgs (>6) — out of scope, like all of Bitcoin |
| Model substitution    | model_id is hashed into every signature; substituting weights breaks future audits      | First-principles "is this the *right* model" — needs zkML/opML on top |

Notice the last row. VERITAS is *not* zkML. It proves *who attested* and *what they attested to*. It does not (yet) prove *that the claimed model actually produced the output*. That's an obvious extension (opML challenge, or a TEE attestation) but it is deliberately out of scope for v1.

---

## What's actually implemented in this repository

- ✅ Real BIP-340 Schnorr signing & verification (via `coincurve` / libsecp256k1).
- ✅ Real NIP-01 Nostr event construction & signature.
- ✅ Real Bitcoin-style double-SHA-256 Merkle trees with inclusion proofs.
- ✅ Real Bitcoin transaction construction for OP_RETURN anchors (P2WPKH signet).
- ✅ HTTP oracle service (FastAPI) with L402-style 402 challenge + preimage gate.
- ✅ CLI subscriber that verifies every layer independently.
- ✅ Plain keyword sentiment model (placeholder; meant to be swapped for the user's existing sentiment agent).
- ✅ FastAPI dashboard.

- 🟡 Real broadcast to a Nostr relay or to Bitcoin signet: **off by default**, behind explicit flags.
- 🟡 Real Lightning node integration: **stubbed**. The L402 layer accepts a "mock preimage" and is structured so an LND/CLN/Phoenixd backend can be dropped in.
- 🟡 Real opML/zkML attestation that the *model* matched: out of scope.

The code is structured so each "🟡" item has a single integration surface.

# VERITAS

**Bitcoin-anchored attestation oracle.** Signs claims with BIP-340 Schnorr keys, publishes them as Nostr events, batches them into Bitcoin-style Merkle trees, and anchors each epoch root to Bitcoin via `OP_RETURN`. Premium streams are gated behind L402 Lightning paywalls.

Trust collapses from *"trust the publisher"* to *"trust math and Bitcoin."*

---

## Why this exists

Most "data on Bitcoin" projects in 2026 ask: *how do we put more state on the chain?* VERITAS inverts that. It treats Bitcoin as an **anchor, not a substrate** — keeping all claims off-chain, and using Bitcoin only for the one job it's genuinely best at: making it expensive to lie about the past.

The first attested object class is **AI inference outputs**, because that's where the trust gap is widest right now. But the protocol is fully general — it attests to anything signable.

---

## How it works

For every claim issued by the oracle:

1. The claim is wrapped in an **attestation** — `{model_id, input_hash, output, ts, epoch, oracle_pubkey}`.
2. The attestation is **signed** with a BIP-340 Schnorr key (the same key format used by Bitcoin Taproot, DLC oracles, and Nostr).
3. The signed attestation is **published** as a NIP-01 Nostr event (kind `30078`).
4. Every epoch (default 600s), all attestations are aggregated into a **Bitcoin-style Merkle tree** and the root is committed to Bitcoin via an **`OP_RETURN` anchor transaction**.
5. A **checkpoint Nostr event** (kind `30079`) binds `(epoch, merkle_root, anchor_txid)`.
6. Premium streams are gated behind **L402 Lightning paywalls** — pay-per-call, no accounts, no KYC.

A verifier independently checks four things — Schnorr signature, Nostr event integrity, Merkle inclusion under the anchored root, and (optionally) the anchor transaction on Bitcoin. The oracle could vanish; old attestations remain provable as long as the Bitcoin chain exists and one honest party retained the inclusion proof.

Full architecture and threat model: [`docs/DESIGN.md`](docs/DESIGN.md). Novelty defense and prior-art audit (including the OpenTimestamps overlap): [`docs/CREATIVITY.md`](docs/CREATIVITY.md). Knowledge audit and Web3 landscape scan: [`docs/ANALYSIS.md`](docs/ANALYSIS.md).

---

## Status

**v0.1 — working prototype.** ~2,200 LOC Python, 41 passing tests, end-to-end demo runs clean.

| Layer                       | Real                                                  | Notes                                    |
|-----------------------------|-------------------------------------------------------|------------------------------------------|
| BIP-340 Schnorr signatures  | ✅ libsecp256k1 (via `coincurve`)                      | Same sigs as Nostr / DLC / Taproot       |
| NIP-01 Nostr events         | ✅ canonical event ID + real signature                 | Relay broadcast off by default           |
| Bitcoin-style Merkle trees  | ✅ double-SHA-256, odd-leaf duplication                | SPV-compatible inclusion proofs          |
| Bitcoin anchor transaction  | ✅ valid signed P2WPKH + `OP_RETURN` segwit tx         | Hex emitted; broadcast gated behind flag |
| L402 paywall                | ✅ HMAC macaroons + preimage→hash gate                 | LN backend is mock; LND/CLN swap-ready   |
| Inference models            | ✅ deterministic keyword sentiment + mempool stub      | Swap point: `veritas/models.py`          |

### Roadmap to v1.0

1. Real Lightning backend (Phoenixd or LND) replacing the L402 mock.
2. Real Nostr relay client with multi-relay redundancy.
3. Bitcoin mainnet broadcast with a funded wallet and confirmation policy.
4. FROST threshold signing for the oracle key, eliminating the single-key-leak failure mode.
5. Reference verifier web client (paste a Nostr event ID, get an independent verdict).
6. TEE-based model attestation (closes the "did the claimed model actually produce this output?" gap — currently out of scope).

---

## Quickstart

Requires Python 3.10+.

```bash
git clone https://github.com/Ifasola34/veritas.git
cd veritas
python -m venv .venv && source .venv/bin/activate
pip install -e .

# 1. Generate an oracle key (BIP-340 / Nostr-compatible)
veritas keygen --out oracle.key

# 2. Run a single attestation locally + print everything
veritas attest --key oracle.key --model veritas.sentiment.keyword.v1 \
    "Bullish breakout above resistance, strong rally"

# 3. Run the HTTP oracle server (FastAPI dashboard at http://localhost:8000)
veritas serve --key oracle.key --data-dir ./veritas-data --port 8000

# 4. End-to-end demo: 4 attestations -> Merkle root -> anchor tx -> verify
python examples/end_to_end_demo.py
```

### HTTP API

| Endpoint                | Verb | What it does                                          |
|-------------------------|------|-------------------------------------------------------|
| `/`                     | GET  | Dashboard (HTML)                                      |
| `/health`               | GET  | Liveness + oracle pubkey + current epoch              |
| `/pubkey`               | GET  | x-only Schnorr / Nostr pubkey                         |
| `/models`               | GET  | Registered model IDs                                  |
| `/infer`                | POST | Public attestation: `{model, input}` → signed payload |
| `/infer/premium`        | POST | L402-gated: returns 402 + `WWW-Authenticate`; retry with `Authorization: L402 <macaroon>:<preimage>` |
| `/close-epoch`          | POST | Force-close epoch → Merkle root + checkpoint + anchor tx |
| `/epoch/{n}`            | GET  | Epoch metadata + all attestations                     |
| `/epoch/{n}/proof/{i}`  | GET  | Merkle inclusion proof for attestation `i`            |
| `/demo/reveal/{ph}`     | POST | Demo-only: reveal preimage for a mock invoice         |

### L402 flow

```bash
# 1. unauthorized -> 402 with challenge
$ curl -is -X POST localhost:8000/infer/premium -d '{"model":"...","input":"..."}'
HTTP/1.1 402 Payment Required
WWW-Authenticate: L402 macaroon="...", invoice="lnbc..."

# 2. pay invoice via your Lightning wallet (demo: /demo/reveal/<payment_hash>)
# 3. retry with: Authorization: L402 <macaroon>:<preimage_hex>
# server validates HMAC tag + (SHA-256(preimage) == payment_hash) + caveats
```

---

## Tests

```bash
$ pytest -q
.........................................                                [100%]
41 passed in 0.03s
```

Coverage includes Schnorr sign/verify, Schnorr tamper-rejection, tagged-hash determinism, Merkle inclusion across multiple tree sizes (including odd-leaf and single-leaf), Merkle proof rejection on wrong root or swapped directions, Nostr event roundtrip + tamper detection, anchor transaction construction + `OP_RETURN` layout, anchor key derivation, full oracle lifecycle, persistence to disk, and L402 macaroon HMAC + invoice/preimage roundtrip.

---

## Repository layout

```
.
├── README.md
├── pyproject.toml
├── docs/
│   ├── ANALYSIS.md       Knowledge audit + Web3 landscape scan
│   ├── DESIGN.md         Technical design + threat model
│   └── CREATIVITY.md     Novelty defense + honest prior-art accounting
├── veritas/              The package
│   ├── crypto.py         BIP-340 + tagged hashes + key derivation
│   ├── attestation.py    Canonical signed attestation payload
│   ├── nostr.py          NIP-01 event format
│   ├── merkle.py         Bitcoin-style Merkle tree + proofs
│   ├── anchor.py         OP_RETURN P2WPKH segwit anchor tx builder
│   ├── lightning.py      L402 challenge + macaroons + mock LN backend
│   ├── models.py         Registered inference models (swap point)
│   ├── oracle.py         Long-running oracle daemon
│   ├── server.py         FastAPI HTTP server
│   ├── verifier.py       Pure verifier
│   ├── web.py            HTML dashboard
│   └── cli.py            `veritas` CLI
├── tests/                pytest, 41 tests, ~30ms
└── examples/
    └── end_to_end_demo.py
```

---

## Prior art and what's novel

The anchoring pattern (Merkle root → `OP_RETURN`) is not new — OpenTimestamps has used it since 2016. What VERITAS adds:

- **Semantic identity in the attestation.** OpenTimestamps anchors opaque hashes — proof *something* happened. VERITAS anchors signed claims with a known oracle pubkey and a structured payload — proof *which entity claimed what, when*.
- **Publication and discovery via Nostr.** OpenTimestamps has no publication layer. VERITAS uses NIP-01 events as the carrier, and the Nostr event signature *is* the attestation signature (one keypair, one sig, two uses).
- **Per-call monetization via L402.** No accounts, no API keys, no KYC. The Lightning preimage is the access credential.
- **One BIP-340 key, three uses.** The oracle's single x-only key signs the attestation payload, the Nostr event, and (optionally) DLC-style outcome reveals — no wrapper layers.

VERITAS is **not zkML or opML.** It proves who attested and what they attested to. It does not (yet) prove that the claimed model actually produced the output. That gap is on the roadmap (TEE attestation).

A longer honest accounting of what's derivative and what's novel is in [`docs/CREATIVITY.md`](docs/CREATIVITY.md).

---

## Contributing

Issues and pull requests welcome. Before opening a PR, please run the test suite (`pytest -q`) and confirm it still passes.

## License

MIT — see [`LICENSE`](LICENSE).

## Contact

Issues: GitHub issues on this repo.
Email: `Ifasola34@icloud.com`

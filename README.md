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

**v0.1 — hardened prototype.** ~3,200 LOC Python, **97 passing tests** including a 20-case adversarial verifier suite, end-to-end demo runs clean.

| Layer                       | Real                                                              | Notes                                                            |
|-----------------------------|-------------------------------------------------------------------|------------------------------------------------------------------|
| BIP-340 Schnorr signatures  | ✅ libsecp256k1 (via `coincurve`)                                  | Same sigs as Nostr / DLC / Taproot                               |
| NIP-01 Nostr events         | ✅ canonical event ID + real signature                             | Relay broadcast off by default                                   |
| Bitcoin-style Merkle trees  | ✅ double-SHA-256 + RFC 6962 leaf/internal prefixes                | `size` + `index` in every proof; depth and direction verified    |
| Bitcoin anchor transaction  | ✅ signed P2WPKH + `OP_RETURN` segwit tx                           | Optional broadcast via **mempool.space** or **bitcoind RPC**     |
| `OP_RETURN` payload         | ✅ `tag(4) ‖ version(1) ‖ epoch(8) ‖ leaf_count(4) ‖ root(32)`     | 49 bytes, single-push; verifier cross-checks against the chain   |
| L402 paywall                | ✅ HMAC macaroons + preimage→hash gate + mandatory `exp=` caveat   | **Real LND (REST) and Phoenixd** backends + mock for dev         |
| Verifier binding            | ✅ attestation ↔ Nostr ↔ Merkle ↔ checkpoint ↔ on-chain OP_RETURN  | Refuses `ok=True` if any link is unverified — 20 adversarial tests |
| Inference models            | ✅ deterministic keyword sentiment + mempool stub                  | Swap point: `veritas/models.py`                                  |

### Roadmap to v1.0

1. ~~Real Lightning backend~~ — **shipped**: LND (REST) + Phoenixd (HTTP) backends.
2. Real Nostr relay client with multi-relay redundancy.
3. ~~Bitcoin broadcast path~~ — **shipped**: mempool.space + bitcoind RPC (signet by default; mainnet is one env var). A funded-wallet confirmation policy is still operator-side.
4. FROST threshold signing for the oracle key, eliminating the single-key-leak failure mode.
5. Reference verifier web client (paste a Nostr event ID, get an independent verdict).
6. TEE-based model attestation (closes the "did the claimed model actually produce this output?" gap — currently out of scope).

### Security posture

VERITAS has been through two rounds of full-codebase code review with all findings patched (commits `97c718c`, `db04588`) and a dedicated adversarial test suite (`tests/test_verifier_adversarial.py`) that names 20 attacks the verifier must refuse — wrong epoch, foreign oracle, mismatched root, truncated/adversarial tx hex, swapped indices, checkpoint or anchor supplied without a proof, etc. Each is an automated regression dam: any future change that weakens a binding check fails these tests before reaching production.

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
| `/demo/reveal/{ph}`     | POST | Demo-only: reveal preimage for a mock invoice. Mounted only when `VERITAS_DEMO=1`. |

### L402 flow

```bash
# 1. unauthorized -> 402 with challenge
$ curl -is -X POST localhost:8000/infer/premium -d '{"model":"...","input":"..."}'
HTTP/1.1 402 Payment Required
WWW-Authenticate: L402 macaroon="...", invoice="lnbc..."

# 2. pay invoice via your Lightning wallet (demo: /demo/reveal/<payment_hash>)
# 3. retry with: Authorization: L402 <macaroon>:<preimage_hex>
# server validates HMAC tag + (SHA-256(preimage) == payment_hash)
#   + at least one exp= caveat in the future
```

---

## Configuration

Every behavior with security or cost implications is env-driven. Defaults are safe (no broadcast, no demo route, no prod-without-real-backends).

| Env var                       | Default      | What it does                                                                       |
|-------------------------------|--------------|------------------------------------------------------------------------------------|
| `VERITAS_ENV`                 | (unset)      | `prod` refuses to start with mock LN backend or a missing L402 secret.             |
| `VERITAS_L402_SECRET`         | random/proc  | HMAC key for L402 macaroons. Use `hex:<openssl rand -hex 32>` or a ≥16-byte passphrase. Fatal if unset in prod. |
| `VERITAS_DEMO`                | (unset)      | `1` mounts `/demo/reveal/{ph}` and includes preimage hints in 402 responses.       |
| `VERITAS_LN_BACKEND`          | `mock`       | `mock` (dev) \| `lnd` \| `phoenixd`.                                               |
| `VERITAS_LND_URL`             |              | e.g. `https://127.0.0.1:8080` (required for `lnd`).                                |
| `VERITAS_LND_MACAROON`        |              | hex-encoded admin macaroon (`xxd -ps -u -c 1000 admin.macaroon`). Required for `lnd`. |
| `VERITAS_LND_CERT_PATH`       |              | Path to LND's `tls.cert` (optional; uses system CAs if absent).                    |
| `VERITAS_PHOENIXD_URL`        |              | e.g. `http://127.0.0.1:9740` (required for `phoenixd`).                            |
| `VERITAS_PHOENIXD_PASSWORD`   |              | `http-password` from `~/.phoenix/phoenix.conf` (required for `phoenixd`).          |
| `VERITAS_ANCHOR_BROADCAST`    | (unset)      | `1` enables Bitcoin broadcast on `close_epoch`; default is build-but-don't-send.   |
| `VERITAS_BROADCASTER`         | `mempool`    | `mempool` (mempool.space) \| `bitcoind` (JSON-RPC).                                |
| `VERITAS_BTC_NETWORK`         | `signet`     | `mainnet` \| `testnet` \| `signet` (mempool.space only).                           |
| `VERITAS_BTC_RPC_URL`         |              | e.g. `http://127.0.0.1:18443` (required for `bitcoind`).                           |
| `VERITAS_BTC_RPC_USER` / `…_PASS` |          | Optional basic-auth credentials for bitcoind.                                      |

A production-prod example:

```bash
export VERITAS_ENV=prod
export VERITAS_L402_SECRET="hex:$(openssl rand -hex 32)"
export VERITAS_LN_BACKEND=lnd
export VERITAS_LND_URL=https://lnd.example.com:8080
export VERITAS_LND_MACAROON=$(xxd -ps -u -c 1000 ~/.lnd/admin.macaroon)
export VERITAS_LND_CERT_PATH=~/.lnd/tls.cert
export VERITAS_ANCHOR_BROADCAST=1
export VERITAS_BTC_NETWORK=mainnet   # or signet to start
veritas serve --key oracle.key --data-dir ./veritas-data --port 8000
```

---

## Tests

```bash
$ pytest -q
.......................................................................... [ 76%]
.......................                                                     [100%]
97 passed in 0.21s
```

Coverage includes:

- **Primitives** — Schnorr sign/verify and tamper-rejection, tagged-hash determinism.
- **Merkle (RFC 6962 + size binding)** — inclusion across multiple sizes incl. odd-leaf and single-leaf; proof rejection on wrong root, swapped directions, inconsistent `size`, out-of-range `index`.
- **Nostr** — canonical event ID + signature roundtrip + tamper detection.
- **Anchor tx** — `OP_RETURN` layout (49 bytes), `build_op_return_payload` roundtrip via `parse_op_return_payload`, extract OP_RETURN from raw segwit tx hex, rejection of mismatched-UTXO-pubkey signing, anchor key derivation.
- **Oracle** — full attest → close → verify lifecycle, persistence to disk with atomic writes, load-from-disk recovery, `inclusion_proof` under lock.
- **L402** — HMAC roundtrip, invoice/preimage flow, resource and expiry caveat enforcement.
- **Real LN backends** — LND request shape, headers, settled/open/404 handling; Phoenixd request shape, basic auth, msat→sat rounding, 404 handling.
- **Bitcoin broadcasters** — mempool.space success/HTTP-error/network-error; bitcoind RPC success-with-auth/error/transport-failure; env-driven factory selection.
- **Adversarial verifier** — 20 named attacks that `verify_full` must refuse (see `tests/test_verifier_adversarial.py`).

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
│   ├── merkle.py         RFC-6962-prefixed Merkle tree + size-bound proofs
│   ├── anchor.py         OP_RETURN payload + segwit tx builder + raw-tx parser
│   ├── broadcast.py      Bitcoin broadcasters (mempool.space, bitcoind RPC, null)
│   ├── lightning.py      L402 macaroons + mock + LND REST + Phoenixd backends
│   ├── models.py         Registered inference models (swap point)
│   ├── oracle.py         Long-running oracle daemon (atomic persistence + reload)
│   ├── server.py         FastAPI HTTP server (env-driven backend + secret)
│   ├── verifier.py       Pure verifier with full binding chain
│   ├── web.py            HTML dashboard
│   └── cli.py            `veritas` CLI
├── tests/                pytest, 97 tests including 20 adversarial verifier cases
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

VERITAS is **not zkML or opML.** It proves who attested and what they attested to, and binds every claim back to the Bitcoin chain. It does not (yet) prove that the claimed model actually produced the output. That gap is on the roadmap (TEE attestation).

A longer honest accounting of what's derivative and what's novel is in [`docs/CREATIVITY.md`](docs/CREATIVITY.md).

---

## Contributing

Issues and pull requests welcome. Before opening a PR, please run the test suite (`pytest -q`) and confirm it still passes.

## License

MIT — see [`LICENSE`](LICENSE).

## Contact

Issues: GitHub issues on this repo.
Email: `Ifasola34@icloud.com`

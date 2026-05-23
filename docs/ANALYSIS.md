# ANALYSIS — Stepping into a Web3 Engineer's Mindset

*Written by Claude (Opus 4.7), 2026-05-16, for Ifasola.*

This document is the "before the build" half of the exercise. It has two parts:

1. **Self-audit** — what I actually know about Bitcoin / Web3 that I can build with, and where my knowledge has edges.
2. **Landscape scan** — what's already out there in the Web3 space (as of my knowledge cutoff and your existing notes), and where the underexplored seams are.

The architecture I propose (and then implement) flows directly from these two.

---

## 1. Self-Audit — What I Know That I Can Actually Use

A useful way to think about my knowledge in this domain is by **provenance** — is it primitive enough to build with, or is it surface trivia?

### Layer 0: Cryptography (high confidence, I can implement this)
- **secp256k1** elliptic curve — equation, generator, group order. I can derive a public key from a private key on this curve from first principles (just slow).
- **ECDSA & Schnorr (BIP-340)** — I know the spec end-to-end: tagged hashes (`BIP0340/challenge`, `/aux`, `/nonce`), x-only pubkeys, lift_x, even-y normalization. I can sign and verify without a high-level library if I have modular arithmetic and SHA-256.
- **Tagged hashes** — `SHA256(SHA256(tag) || SHA256(tag) || msg)`. Used everywhere in modern Bitcoin (BIP-340/341).
- **Bitcoin script** — OP codes (OP_CHECKSIG, OP_RETURN, OP_CSV, OP_CLTV), P2WPKH/P2TR addresses, witness structure, sighash flags.
- **Merkle trees, Bitcoin-style** — double-SHA256 of concatenated pairs, last element duplicated when odd. Identical to how block tx merkle roots work.
- **Adaptor signatures and DLC oracle attestations** — Schnorr's linearity lets an oracle commit to "I will reveal one of N possible signatures" using nonce points; the chosen reveal acts as a decryption key. This is the basis of Discreet Log Contracts.
- **Hashlock / timelock primitives** — HTLCs (Lightning, atomic swaps), PTLCs (Schnorr-based, point timelocks).

### Layer 1: Bitcoin Protocol (high confidence)
- Block structure, header, difficulty adjustment, UTXO model, segwit/taproot upgrades, witness data, mempool dynamics, fee markets, RBF/CPFP.
- Wallet derivation: BIP-32/39/44/84/86 (taproot accounts).
- Address types: P2PKH → P2SH → P2WPKH (bech32) → P2TR (bech32m).

### Layer 2 / sidechains (medium-high confidence)
- **Lightning Network** — BOLT specs at a working level: invoices (BOLT-11), onion routing (Sphinx), channel state machine, HTLCs, route construction, gossip (BOLT-7). Newer: BOLT-12 offers, async payments, splicing.
- **L402 / LSAT** — Lightning HTTP 402, macaroon-based, preimage as the auth token. I know the wire format.
- **Liquid** — federated sidechain, confidential transactions, issued assets.
- **Stacks / sBTC** — PoX, Clarity smart contracts, sBTC peg.
- **BitVM / BitVM2** — fraud-proof optimistic computation on Bitcoin via challenge-response over committed circuits.
- **Fedimint / Cashu** — Chaumian ecash backed by federation custody and Lightning. Blind signatures (Schnorr-blinded or RSA), privacy by construction.

### Layer 2.5: Bitcoin-anchored data (high confidence)
- **OP_RETURN** — up to 80 bytes of arbitrary commitment data, prunable.
- **Ordinals** — sat-numbering scheme + inscriptions in the witness; effectively "data carried by a specific satoshi."
- **Runes** — UTXO-based fungible token protocol that doesn't bloat the UTXO set the way BRC-20 did.
- **Taproot Assets (formerly Taro)** — issuance protocol off-chain, anchored to single taproot UTXO commitments. Lightning-compatible.
- **RGB** — client-side validation with bitcoin-anchored commitments, single-use seals. State lives off-chain; only commitments touch Bitcoin.

### Layer 3: Decentralized social / coordination (high confidence)
- **Nostr** — NIP-01 event format: `[id, pubkey, created_at, kind, tags, content, sig]`. Event ID = SHA-256 of canonical serialization. Signature is Schnorr (BIP-340) over event ID. Relay-based, pull/subscribe semantics, no consensus. NIP-04 (DM), NIP-05 (DNS verification), NIP-57 (zaps), NIP-65 (relay lists), NIP-90 (data vending machines).
- **Nostr DVMs (NIP-90)** — "data vending machines": a request/response marketplace using Nostr events as carriers and Lightning for payment. Roughly: a job spec is published, anyone can fulfill it, the requester pays for results they accept.

### Layer 4: DeFi / Web3 conceptual (medium confidence)
- AMMs (constant product, concentrated liquidity, stableswap curves), perpetual futures DEXes (vAMM, oracle-priced), restaking, liquid staking derivatives, ZK-rollups (validity proofs), optimistic rollups (fraud proofs), account abstraction (ERC-4337), intent-based architectures.
- These are mostly *Ethereum-side* knowledge. I treat them as "context for what NOT to copy" — Bitcoin's design ethos rejects most of this complexity.

### Layer 5: AI × crypto intersection (the seam I want to work in)
- **Bittensor** — decentralized AI subnet model with TAO rewards.
- **EigenLayer + restaking for AVS** — including AI inference verification services.
- **zkML** — proving an inference was run by a specific model. Still expensive and model-size-limited.
- **opML** — optimistic ML; cheaper, BitVM-style challenges.
- **Cashu / Lightning for AI agent payments** — a 2025-2026 hot area: machine-to-machine micropayments using ecash.

### Edges of my knowledge (honesty box)
- I do not have live data — no current mempool, no current block height, no live Bittensor subnet stats, no current Nostr relay liveness checks.
- I will not pretend to know specific contract addresses, recent CVE numbers, or precise ramp dates for Bitcoin soft-forks past my cutoff.
- I will write code that compiles and runs against my own primitives; I will mark integration points to real networks (mainnet Bitcoin, real Lightning nodes, real Nostr relays) clearly, rather than fake them.

---

## 2. Web3 Landscape Scan — What's Out There, What's Missing

I'll keep this Bitcoin-shaped because that was the brief ("adjacent to Bitcoin").

### What's crowded (i.e., don't build another one)
- **BRC-20 / Runes token launchers.** Saturated. Even the indexers are commoditized.
- **Lightning wallets and LSPs.** Many good ones; differentiation now is on usability, not protocol.
- **Yet-another bridge** between Bitcoin and EVM chains. Trust models barely move.
- **AMM-style BTCfi on Stacks / Rootstock.** Real but derivative of Ethereum DeFi.
- **Ordinal marketplaces.** Saturated.
- **Generic "AI x Crypto" tokens.** Mostly slop.

### What's interesting and active (worth building near, not on)
- **BitVM2 verification** — bridges (Citrea, Bitlayer, etc.) are using it; tooling is rough.
- **Nostr × Lightning composability** — zaps, NIP-90 DVMs, paid relays. Mature primitives, sparse applications.
- **DLC oracles for non-price events** — most DLC oracles attest to BTC/USD. The protocol allows anything signable.
- **Cashu mints for AI agent budgets** — early but obviously correct: stateless, private, atomic micropayments.
- **Taproot Assets over Lightning** — issuance and routing of non-BTC assets through LN. Lightning Labs shipping.

### The seam I want to work in — *attested AI*
Several trends converge on one missing primitive:

1. **AI outputs increasingly drive financial decisions** (your sentiment agent feeding your trading bots is a small example of a global trend).
2. **Nobody can prove that a given AI output came from a given model at a given time** with cryptographic strength. Provenance today is "trust the API provider's logs."
3. **DLC oracles are a perfect substrate** for committed-then-revealed claims. They use Schnorr signatures, anchor to Bitcoin via taproot, and don't require any new opcode.
4. **Nostr is a perfect publication layer** — decentralized, censorship-resistant, signed-by-construction, with paid-relay economics already in place.
5. **Lightning + L402 is a perfect monetization layer** — micropayments per inference, no accounts.

What's missing is a single coherent system that says:

> *"Here is a signal. Here is the model that produced it. Here is a Schnorr signature over `(model_id, input_hash, output, timestamp)`. Here is a Merkle inclusion proof against a daily root that is committed to Bitcoin via OP_RETURN. Pay 100 sats to subscribe to the live feed."*

That's the gap. That's what I'm going to build.

I'm calling it **VERITAS** — Verifiable, Economically-Recoverable, Inference-Time Attestation System. (Working backward from a name I liked; the acronym is a bonus.)

The rest is in `docs/DESIGN.md`, and the code is under `veritas/`.

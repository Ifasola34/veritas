# Try VERITAS yourself — a ~15-minute walkthrough

**What VERITAS does, in one line:** it lets an AI *sign* what it did and stamp a tamper-proof fingerprint of it onto Bitcoin — so anyone can later prove the record is genuine and unaltered, **without trusting the company that made it.**

This guide goes: (1) *see* a real one in your browser, (2) *run the whole thing yourself*, (3) the honest version of "putting it on Bitcoin." If parts 1 and 2 work for you, you've got it.

---

## Part 1 — See a real one (no install, ~2 minutes)
1. Open **https://vrt1-web-verifier.pages.dev**
2. Click **"Run a live verification."** Watch the layers turn green — signature, public receipt, batch proof, checkpoint, and the **Bitcoin anchor**.
3. Don't take the page's word for it — click the **Bitcoin transaction** link (mempool.space). That's a real, permanent transaction on Bitcoin mainnet (since 13 June 2026), and the fingerprint of an AI attestation is inside it.

✅ **What you just proved:** a real AI claim, anchored to Bitcoin, that *anyone* can independently verify with public math.

---

## Part 2 — Do it yourself (install + run, ~10 minutes)
You need **Python 3.10+** and a terminal.

```bash
git clone https://github.com/Ifasola34/veritas.git
cd veritas
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

**Run the whole machine end-to-end:**
```bash
python examples/end_to_end_demo.py
```
You'll watch it create 4 AI attestations → bundle them into a Merkle tree → build the **Bitcoin anchor transaction** → independently verify every layer (all **VERIFIED**) → and then catch a **forged** record (**rejected**). That's the entire VERITAS chain, on real cryptography, on your own machine.

**Now sign YOUR OWN words:**
```bash
veritas keygen --out oracle.key
veritas attest --key oracle.key --model veritas.sentiment.keyword.v1 "Write anything you want here"
```
It prints a signed attestation of *your* input: the model's output, a fingerprint of your text (`input_hash`), and an unforgeable **signature**. Change one character of the input and the fingerprint changes; tamper with the record and the signature won't match. That signature is what makes the record **provably yours and tamper-evident.**

✅ **What you just proved:** you can produce a real, signed, independently-verifiable AI record yourself — and the system catches fakes.

---

## Part 3 — Putting your own record on Bitcoin (the honest version)
The demo *builds* a real Bitcoin anchor transaction (you saw the raw hex) but doesn't broadcast it — putting it on the live chain costs a tiny network fee and needs a funded Bitcoin wallet.

- **The free way to try it for real:** VERITAS defaults to **signet** (Bitcoin's *free* test network). With free signet coins from a faucet, it will broadcast a real anchor there at no cost. (A few more steps — ask whoever shared this with you if you want to go that far.)
- **Mainnet (real Bitcoin)** is a single setting change — that's how the genesis you verified in Part 1 was made.

🔑 **The key idea:** signing is free and instant, and **one** Bitcoin transaction can certify an *unlimited batch* of attestations — so anchoring stays cheap at any scale.

---

## Takeaways
- Anyone can verify a VERITAS record with public math — **no account, no trusting the maker.**
- The **signature** proves who made the claim and that it hasn't been altered.
- **Bitcoin** proves it existed by a certain time and can't be quietly rewritten.

That's the whole idea: *trust no one, check it yourself.* If the demo ran green and you attested your own sentence, you understand VERITAS.

_Questions? Ask the person who shared this with you._

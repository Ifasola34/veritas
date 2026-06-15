# Try VERITAS yourself: a ~15-minute walkthrough

**What VERITAS does, in one line:** it lets an AI *sign* what it did and stamp a tamper-proof fingerprint of it onto Bitcoin, so anyone can later prove the record is genuine and unaltered, **without trusting the company that made it.**

This guide goes: (1) *see* a real one in your browser, (2) *run the whole thing yourself*, (3) the honest version of "putting it on Bitcoin." If parts 1 and 2 work for you, you've got it.

---

## Part 1: See a real one (no install, ~2 minutes)
1. Open **https://vrt1-web-verifier.pages.dev**
2. Click **"Run a live verification."** Watch the layers turn green: signature, public receipt, batch proof, checkpoint, and the **Bitcoin anchor**.
3. Don't take the page's word for it. Click the **Bitcoin transaction** link (mempool.space). That's a real, permanent transaction on Bitcoin mainnet (since 13 June 2026), and the fingerprint of an AI attestation is inside it.

✅ **What you just proved:** a real AI claim, anchored to Bitcoin, that *anyone* can independently verify with public math.

---

## Part 2: Do it yourself (install + run, ~10 minutes)
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

✅ **What you just proved:** you can produce a real, signed, independently-verifiable AI record yourself, and the system catches fakes.

---

## Prefer to let your AI agent drive?
You don't have to run anything yourself. Paste the box below to your AI coding agent (Claude Code, Cursor, etc.) **along with this file**:

```
Walk me through VERITAS using the attached TRY-IT guide. Please:
1. Read the whole guide, then explain in plain English what we're about to prove and why it matters.
2. Part 1: don't just trust the verifier site. Independently look up the Bitcoin transaction on a public block explorer (e.g. mempool.space) and confirm the AI attestation's fingerprint is really on-chain.
3. Part 2: run it in my terminal for me. Clone the repo, set up the environment, run the end-to-end demo, then sign a sentence I give you. Show the output and explain what each result proves, including the "forged record rejected" step.
4. Stop before Part 3 (broadcasting to Bitcoin). Explain my options first: it's optional, needs a funded wallet, and may cost a small fee. That decision is mine, not yours.
Stay skeptical and verify each layer yourself as you go. The whole point of VERITAS is "trust no one, check it yourself."
```

---

## Part 3: Putting your own record on Bitcoin (the honest version)
The demo *builds* a real Bitcoin anchor transaction (you saw the raw hex) but doesn't broadcast it: putting it on the live chain costs a tiny network fee and needs a funded Bitcoin wallet.

- **The free way to try it for real:** VERITAS defaults to **signet** (Bitcoin's *free* test network). With free signet coins from a faucet, it will broadcast a real anchor there at no cost. (A few more steps; ask whoever shared this with you if you want to go that far.)
- **Mainnet (real Bitcoin)** is a single setting change. That's how the genesis you verified in Part 1 was made.

🔑 **The key idea:** signing is free and instant, and **one** Bitcoin transaction can certify an *unlimited batch* of attestations, so anchoring stays cheap at any scale.

---

## Takeaways
- Anyone can verify a VERITAS record with public math: **no account, no trusting the maker.**
- The **signature** proves who made the claim and that it hasn't been altered.
- **Bitcoin** proves it existed by a certain time and can't be quietly rewritten.

That's the whole idea: *trust no one, check it yourself.* If the demo ran green and you attested your own sentence, you understand VERITAS.

_Questions? Ask the person who shared this with you._

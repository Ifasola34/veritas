# Signet anchor example

Make a real VERITAS attestation and anchor it to **Bitcoin's signet test
network**, for free. Signet coins have no monetary value, so this is the safe
way to watch the whole pipeline (sign, Merkle, `OP_RETURN` anchor, broadcast)
produce a real, look-it-up-yourself Bitcoin transaction.

## Prerequisites
Python 3.10+ and this repo installed: from the repo root, `pip install -e .`

## Steps
1. Generate a fresh oracle key and print its signet funding address:
   ```
   python make_address.py
   ```
   Copy the printed `tb1q...` address.
2. Fund that address at a free signet faucet, e.g. https://signetfaucet.com . Any amount works (the anchor costs only a few hundred test-sats).
3. Build and broadcast the anchor:
   ```
   python anchor.py
   ```
   It prints the anchor `txid` and a `mempool.space/signet/tx/...` link.
4. Open that link and scroll to the `OP_RETURN` output. That is the attestation's fingerprint, committed to Bitcoin.

Your `oracle.key` and `artifacts/` stay local (gitignored). Nothing here touches mainnet.

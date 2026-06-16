# Mainnet anchor example

Make a real VERITAS attestation and anchor it to **Bitcoin mainnet**.

> **⚠️ This spends real Bitcoin.** The fee is tiny (typically well under $1), but
> it is real money. Want to watch the whole pipeline for free first? Use
> [`../signet-anchor`](../signet-anchor) — identical steps on Bitcoin's free
> test network.

## Prerequisites
Python 3.10+ and this repo installed: from the repo root, `pip install -e .`

## Steps
1. Generate a fresh oracle key and print its mainnet funding address:
   ```
   python make_address.py
   ```
   Copy the printed `bc1q...` address.
2. Fund that address from your own wallet with a dollar or two of BTC, and wait
   for **1 confirmation**. (The anchor needs only the network fee + dust.)
3. Build and broadcast the anchor:
   ```
   python anchor.py
   ```
   It builds the transaction, shows you the exact tx, the fee, and the cost in
   USD, then asks you to type `yes` before it broadcasts anything. On
   confirmation it prints the `txid` and a `mempool.space/tx/...` link.
   (Pass `--yes` to skip the prompt.)
4. Open that link and scroll to the `OP_RETURN` output — that is your
   attestation's fingerprint, committed to Bitcoin mainnet. Anyone can verify it
   at <https://vrt1-web-verifier.pages.dev>.

To attest your own statement, edit `TEXT` near the top of `anchor.py` before
step 3.

Your `oracle.key` and `artifacts/` stay local (gitignored).

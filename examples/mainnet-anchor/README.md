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

## Getting your BTC back

After anchoring, your change (everything except the fee) is back at your
`bc1q...` funding address. **First wait for the anchor transaction to confirm
(1 block)** — the sweep only spends *confirmed* coins, so running it sooner just
reports `No confirmed BTC to sweep`. Once it's in a block, move the change to
your own wallet:

```
python sweep.py bc1qYOUR_OWN_ADDRESS
```

Replace `bc1qYOUR_OWN_ADDRESS` with a real receive address **from your own
wallet** — native segwit (`bc1q...`) or legacy (`1.../3...`), **not** a Taproot
`bc1p...` address. (Paste the placeholder verbatim and the script stops and
tells you to use your own address; a mistyped address fails its checksum, so
funds can't be sent into the void.) It shows the amount and fee and asks you to
type `yes` before sending. (`--yes` skips the prompt; `--rate N` sets the fee
rate in sat/vB.)

To attest your own statement, pass it on the command line:
`python anchor.py --text "your statement"` (or edit the `TEXT` line near the top
of `anchor.py`).

Your `oracle.key` and `artifacts/` stay local (gitignored).

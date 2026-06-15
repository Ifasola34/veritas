"""End-to-end VERITAS demo, walks through every layer.

Run:  python examples/end_to_end_demo.py
"""

import json
import tempfile
from pathlib import Path

from coincurve import PrivateKey
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table

from veritas.anchor import Utxo
from veritas.attestation import attestation_digest
from veritas.crypto import OracleKey, derive_anchor_key
from veritas.merkle import verify_merkle_proof
from veritas.nostr import decode_attestation_event
from veritas.oracle import Oracle, OracleConfig
from veritas.verifier import verify_full


console = Console()


def main() -> None:
    console.print(Rule("[bold yellow]VERITAS  end-to-end  demo"))

    # --- 1. Oracle setup ----------------------------------------------------
    okey = OracleKey.generate()
    anchor_priv = derive_anchor_key(okey)
    anchor_pk = PrivateKey(anchor_priv).public_key.format(compressed=True)
    # A pretend funded UTXO. In practice you'd query a signet wallet.
    utxo = Utxo(
        txid="ab" * 32, vout=0, value_sats=100_000,
        pubkey_compressed=anchor_pk,
    )
    with tempfile.TemporaryDirectory() as tmp:
        oracle = Oracle(okey, OracleConfig(
            data_dir=Path(tmp),
            anchor_utxo=utxo,
            fee_sats=400,
            epoch_seconds=999_999,  # never auto-roll during demo
        ))
        console.print(Panel.fit(
            f"oracle pubkey  [green]{oracle.pubkey_hex}[/green]\n"
            f"anchor pubkey  [yellow]{anchor_pk.hex()}[/yellow]\n"
            f"data dir       {tmp}",
            title="1. oracle initialised",
            title_align="left",
        ))

        # --- 2. Inferences --------------------------------------------------
        console.print(Rule("2. inferences + attestations"))
        inputs = [
            ("veritas.sentiment.keyword.v1",
             "Bullish breakout above resistance, strong rally, accumulate longs"),
            ("veritas.sentiment.keyword.v1",
             "Bearish rejection, capitulation dump, weak buyers"),
            ("veritas.sentiment.keyword.v1",
             "Choppy range, no edge here"),
            ("veritas.mempool.pressure.v1", "sat/vB ~ 18 pending 47000"),
        ]
        signed_list, event_list = [], []
        t = Table()
        t.add_column("#"); t.add_column("model"); t.add_column("output"); t.add_column("digest")
        for i, (model, text) in enumerate(inputs):
            signed, evt = oracle.attest(model, text)
            signed_list.append(signed)
            event_list.append(evt)
            t.add_row(
                str(i), model, json.dumps(signed.attestation.output),
                attestation_digest(signed.attestation).hex()[:16] + "…",
            )
        console.print(t)

        # --- 3. Close epoch -> Merkle root + anchor tx ----------------------
        console.print(Rule("3. close epoch  →  Merkle root + Bitcoin anchor"))
        epoch = oracle.close_epoch()
        console.print(f"closed epoch [bold]{epoch.number}[/bold]")
        console.print(f"merkle root: [green]{epoch.root_hex}[/green]")
        console.print(f"anchor txid: [yellow]{epoch.anchor_tx.txid}[/yellow]")
        console.print("OP_RETURN payload:")
        console.print(f"  [cyan]{epoch.anchor_tx.op_return_payload.hex()}[/cyan]")
        console.print(
            "raw transaction hex (broadcastable on signet once UTXO is real):"
        )
        console.print(Syntax(epoch.anchor_tx.raw_hex, "text",
                             background_color="default", word_wrap=True))

        # --- 4. Independent verifier ----------------------------------------
        console.print(Rule("4. independent verifier"))
        for i, signed in enumerate(signed_list):
            evt = event_list[i]
            proof = oracle.inclusion_proof(epoch.number, i)
            decoded = decode_attestation_event(evt)
            r = verify_full(
                signed=decoded,
                nostr_event=evt,
                proof=proof,
                checkpoint_event=epoch.checkpoint_event,
            )
            tag = "[green]VERIFIED[/green]" if r.ok else "[red]REJECTED[/red]"
            console.print(
                f"  att #{i}: schnorr={r.schnorr_ok} nostr={r.nostr_event_ok} "
                f"merkle={r.merkle_ok} checkpoint={r.checkpoint_ok}  →  {tag}"
            )

        # --- 5. Tamper detection --------------------------------------------
        console.print(Rule("5. tamper detection"))
        bad = signed_list[1]
        original_output = bad.attestation.output
        bad.attestation.output = {"label": "bullish", "score": 1.0}  # forge!
        r = verify_full(signed=bad)
        console.print(
            f"  forged output → schnorr_ok={r.schnorr_ok}  "
            f"[{'green]✓ rejected[/green' if not r.ok else 'red]LEAKED THROUGH[/red'}]"
        )
        bad.attestation.output = original_output  # restore for cleanliness

        console.print(Rule("[bold yellow]demo complete"))


if __name__ == "__main__":
    main()

"""VERITAS command-line interface."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from .anchor import Utxo
from .attestation import SignedAttestation, attestation_digest
from .broadcast import make_broadcaster
from .crypto import OracleKey
from .lightning import DeterministicMockBackend, authorize, make_challenge
from .merkle import verify_merkle_proof, MerkleProof
from .nostr import NostrEvent, decode_attestation_event
from .oracle import Oracle, OracleConfig
from .verifier import verify_full


console = Console()


@click.group()
def cli() -> None:
    """VERITAS — Bitcoin-anchored AI attestation oracle."""


@cli.command()
@click.option("--out", type=click.Path(), default="oracle.key")
def keygen(out: str) -> None:
    """Generate a fresh oracle BIP-340 keypair."""
    key = OracleKey.generate()
    # Atomic create with restrictive mode: refuses to overwrite, no
    # TOCTOU window where another local process can read the privkey.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(out, flags, 0o600)
    except FileExistsError:
        raise click.ClickException(
            f"refusing to overwrite existing key file: {out}"
        )
    except OSError as e:
        raise click.ClickException(f"cannot create key file {out}: {e}")
    try:
        os.write(fd, (key.privkey.hex() + "\n").encode("ascii"))
    finally:
        os.close(fd)
    console.print(Panel.fit(
        f"[bold green]Key created[/bold green]\n"
        f"x-only pubkey: [yellow]{key.xonly_pubkey_hex}[/yellow]\n"
        f"saved private key → {out} (mode 0600)"
    ))


@cli.command()
@click.option("--key", "key_path", type=click.Path(exists=True), default="oracle.key")
@click.option("--data-dir", type=click.Path(), default="./veritas-data")
@click.option("--epoch-seconds", type=int, default=600)
@click.option("--port", type=int, default=8000)
@click.option("--host", type=str, default="127.0.0.1")
def serve(key_path: str, data_dir: str, epoch_seconds: int, host: str, port: int) -> None:
    """Run the oracle HTTP server."""
    import uvicorn
    from .server import create_app
    key = OracleKey.from_hex(Path(key_path).read_text().strip())
    broadcaster = make_broadcaster()
    oracle = Oracle(key, OracleConfig(
        data_dir=Path(data_dir),
        epoch_seconds=epoch_seconds,
        broadcaster=broadcaster,
    ))
    app = create_app(oracle)
    console.print(Panel.fit(
        f"[bold]VERITAS oracle running[/bold]\n"
        f"pubkey:      [yellow]{oracle.pubkey_hex}[/yellow]\n"
        f"data:        {data_dir}\n"
        f"http:        http://{host}:{port}\n"
        f"broadcaster: {broadcaster.name}\n"
    ))
    uvicorn.run(app, host=host, port=port, log_level="warning")


@cli.command()
@click.option("--key", "key_path", type=click.Path(exists=True), default="oracle.key")
@click.option("--data-dir", type=click.Path(), default="./veritas-data")
@click.option("--model", required=True)
@click.argument("text")
def attest(key_path: str, data_dir: str, model: str, text: str) -> None:
    """Run a single inference + attestation locally and print everything."""
    key = OracleKey.from_hex(Path(key_path).read_text().strip())
    oracle = Oracle(key, OracleConfig(data_dir=Path(data_dir)))
    signed, evt = oracle.attest(model, text)
    digest = attestation_digest(signed.attestation).hex()

    t = Table(title="Attestation", show_header=False)
    t.add_row("model", signed.attestation.model)
    t.add_row("output", json.dumps(signed.attestation.output))
    t.add_row("input_hash", signed.attestation.input_hash)
    t.add_row("epoch", str(signed.attestation.epoch))
    t.add_row("oracle pubkey", signed.attestation.oracle)
    t.add_row("ts", str(signed.attestation.ts))
    t.add_row("digest (signed)", digest)
    t.add_row("sig", signed.sig)
    console.print(t)

    console.print(Panel(
        Syntax(json.dumps(evt.to_dict(), indent=2), "json",
               background_color="default"),
        title="NIP-01 Nostr event",
        title_align="left",
    ))


@cli.command()
@click.option("--key", "key_path", type=click.Path(exists=True), default="oracle.key")
@click.option("--data-dir", type=click.Path(), default="./veritas-data")
def close(key_path: str, data_dir: str) -> None:
    """Force-close the current epoch and print the anchor."""
    key = OracleKey.from_hex(Path(key_path).read_text().strip())
    broadcaster = make_broadcaster()
    oracle = Oracle(key, OracleConfig(
        data_dir=Path(data_dir),
        broadcaster=broadcaster,
    ))
    e = oracle.close_epoch()
    console.print(f"closed epoch [bold]{e.number}[/bold] with {len(e.attestations)} attestations")
    if e.root_hex:
        console.print(f"merkle root: [green]{e.root_hex}[/green]")
    if e.anchor_tx:
        console.print(f"anchor txid: [yellow]{e.anchor_tx.txid}[/yellow]")
        console.print(f"OP_RETURN  : [cyan]{e.anchor_tx.op_return_payload.hex()}[/cyan]")
        console.print("tx hex     :")
        console.print(Syntax(e.anchor_tx.raw_hex, "text", background_color="default", word_wrap=True))
    if e.broadcast_result and e.broadcast_result.backend != "null":
        status = "[bold green]broadcast OK[/bold green]" if e.broadcast_result.ok \
            else "[bold red]broadcast FAILED[/bold red]"
        console.print(f"{status} via {e.broadcast_result.backend}")
        if e.broadcast_result.txid:
            console.print(f"network txid: [yellow]{e.broadcast_result.txid}[/yellow]")
        if e.broadcast_result.error:
            console.print(f"error: [red]{e.broadcast_result.error}[/red]")


@cli.command()
@click.argument("attestation_file", type=click.Path(exists=True))
@click.option("--event-file", type=click.Path(exists=True), required=False)
@click.option("--proof-file", type=click.Path(exists=True), required=False)
@click.option("--checkpoint-file", type=click.Path(exists=True), required=False)
@click.option("--anchor-raw-hex", type=str, required=False,
              help="Raw Bitcoin anchor tx hex (e.g. from a block explorer); "
                   "verifier cross-checks OP_RETURN against the checkpoint.")
def verify(attestation_file: str, event_file: str | None,
           proof_file: str | None, checkpoint_file: str | None,
           anchor_raw_hex: str | None) -> None:
    """Verify a saved attestation (and optionally proof + checkpoint + anchor tx)."""
    def _load_nostr_event(d: dict) -> NostrEvent:
        # Filter to known fields so future schema additions don't crash.
        known = {"pubkey", "created_at", "kind", "tags", "content", "id", "sig"}
        missing = {"pubkey", "created_at", "kind"} - d.keys()
        if missing:
            raise click.ClickException(f"event missing required fields: {sorted(missing)}")
        return NostrEvent(**{k: v for k, v in d.items() if k in known})

    try:
        signed = SignedAttestation.from_json(Path(attestation_file).read_text())
    except (ValueError, KeyError) as e:
        raise click.ClickException(f"invalid attestation file: {e}")

    evt = None
    if event_file:
        try:
            evt = _load_nostr_event(json.loads(Path(event_file).read_text()))
        except (ValueError, json.JSONDecodeError) as e:
            raise click.ClickException(f"invalid event file: {e}")

    proof = None
    if proof_file:
        try:
            d = json.loads(Path(proof_file).read_text())
            proof = MerkleProof(
                leaf=bytes.fromhex(d["leaf_hex"]),
                siblings=[bytes.fromhex(s) for s in d["siblings_hex"]],
                directions=list(d["directions"]),
                root=bytes.fromhex(d["root_hex"]),
                size=int(d["size"]),
                index=int(d["index"]),
            )
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            raise click.ClickException(f"invalid proof file: {e}")

    cp_event = None
    anchor_hex = anchor_raw_hex
    if checkpoint_file:
        try:
            d = json.loads(Path(checkpoint_file).read_text())
        except json.JSONDecodeError as e:
            raise click.ClickException(f"invalid checkpoint file: {e}")
        if d.get("checkpoint_event"):
            cp_event = _load_nostr_event(d["checkpoint_event"])
        # If the local checkpoint file ships the anchor raw hex and the
        # user didn't override via --anchor-raw-hex, use it.
        if anchor_hex is None and d.get("anchor") and d["anchor"].get("raw_hex"):
            anchor_hex = d["anchor"]["raw_hex"]

    r = verify_full(
        signed=signed,
        nostr_event=evt,
        proof=proof,
        checkpoint_event=cp_event,
        anchor_raw_tx_hex=anchor_hex,
    )
    t = Table(title="Verification result")
    t.add_column("check"); t.add_column("ok?")
    for name, val in [
        ("schnorr (attestation)", r.schnorr_ok),
        ("nostr event", r.nostr_event_ok),
        ("merkle inclusion", r.merkle_ok),
        ("checkpoint", r.checkpoint_ok),
        ("anchor OP_RETURN", r.anchor_ok),
    ]:
        if val is None:
            t.add_row(name, "[grey]n/a[/grey]")
        else:
            t.add_row(name, "[green]✓[/green]" if val else "[red]✗[/red]")
    console.print(t)
    if r.notes:
        console.print("[yellow]notes:[/yellow]")
        for n in r.notes:
            console.print(f"  • {n}")
    console.print(Panel.fit(
        "[bold green]VERIFIED[/bold green]" if r.ok else "[bold red]REJECTED[/bold red]"
    ))


if __name__ == "__main__":
    cli()

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
    Path(out).write_text(key.privkey.hex() + "\n")
    os.chmod(out, 0o600)
    console.print(Panel.fit(
        f"[bold green]Key created[/bold green]\n"
        f"x-only pubkey: [yellow]{key.xonly_pubkey_hex}[/yellow]\n"
        f"saved private key → {out}"
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
    oracle = Oracle(key, OracleConfig(
        data_dir=Path(data_dir),
        epoch_seconds=epoch_seconds,
    ))
    app = create_app(oracle)
    console.print(Panel.fit(
        f"[bold]VERITAS oracle running[/bold]\n"
        f"pubkey: [yellow]{oracle.pubkey_hex}[/yellow]\n"
        f"data:   {data_dir}\n"
        f"http:   http://{host}:{port}\n"
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
    oracle = Oracle(key, OracleConfig(data_dir=Path(data_dir)))
    e = oracle.close_epoch()
    console.print(f"closed epoch [bold]{e.number}[/bold] with {len(e.attestations)} attestations")
    if e.root_hex:
        console.print(f"merkle root: [green]{e.root_hex}[/green]")
    if e.anchor_tx:
        console.print(f"anchor txid: [yellow]{e.anchor_tx.txid}[/yellow]")
        console.print(f"OP_RETURN  : [cyan]{e.anchor_tx.op_return_payload.hex()}[/cyan]")
        console.print("tx hex     :")
        console.print(Syntax(e.anchor_tx.raw_hex, "text", background_color="default", word_wrap=True))


@cli.command()
@click.argument("attestation_file", type=click.Path(exists=True))
@click.option("--event-file", type=click.Path(exists=True), required=False)
@click.option("--proof-file", type=click.Path(exists=True), required=False)
@click.option("--checkpoint-file", type=click.Path(exists=True), required=False)
def verify(attestation_file: str, event_file: str | None,
           proof_file: str | None, checkpoint_file: str | None) -> None:
    """Verify a saved attestation (and optionally proof + checkpoint)."""
    signed = SignedAttestation.from_json(Path(attestation_file).read_text())
    evt = None
    if event_file:
        d = json.loads(Path(event_file).read_text())
        evt = NostrEvent(**d)
    proof = None
    if proof_file:
        d = json.loads(Path(proof_file).read_text())
        proof = MerkleProof(
            leaf=bytes.fromhex(d["leaf_hex"]),
            siblings=[bytes.fromhex(s) for s in d["siblings_hex"]],
            directions=list(d["directions"]),
            root=bytes.fromhex(d["root_hex"]),
        )
    cp_event, cp_root = None, None
    if checkpoint_file:
        d = json.loads(Path(checkpoint_file).read_text())
        cp_root = d.get("root")
        if "checkpoint_event" in d and d["checkpoint_event"]:
            cp_event = NostrEvent(**d["checkpoint_event"])
    r = verify_full(
        signed=signed,
        nostr_event=evt,
        proof=proof,
        checkpoint_event=cp_event,
        checkpoint_root_hex=cp_root,
    )
    t = Table(title="Verification result")
    t.add_column("check"); t.add_column("ok?")
    for name, val in [
        ("schnorr (attestation)", r.schnorr_ok),
        ("nostr event", r.nostr_event_ok),
        ("merkle inclusion", r.merkle_ok),
        ("checkpoint", r.checkpoint_ok),
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

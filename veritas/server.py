"""FastAPI HTTP server exposing the oracle.

Endpoints:
  GET  /              dashboard (HTML)
  GET  /health        liveness
  GET  /pubkey        oracle x-only pubkey (hex)
  GET  /models        list of model_ids
  POST /infer         { model, input } -> SignedAttestation + Nostr event
  POST /infer/premium 402-gated version of /infer (L402)
  POST /close-epoch   force-close current epoch (returns checkpoint + anchor)
  GET  /epoch/{n}     epoch metadata + leaves + Merkle root
  GET  /epoch/{n}/proof/{i}   inclusion proof for attestation i in epoch n
  GET  /verify        client-side verifier UI (returns dashboard with form)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from .attestation import attestation_digest
from .crypto import OracleKey
from .lightning import (
    DeterministicMockBackend,
    L402Challenge,
    authorize,
    make_challenge,
)
from .merkle import MerkleTree
from .oracle import Oracle, OracleConfig


# ----- module-level singleton, initialized by `create_app` -----------

_ORACLE: Oracle | None = None
_LN = DeterministicMockBackend()
_L402_SECRET = b"VRT1-l402-server-secret-replace-me"


class InferReq(BaseModel):
    # `model_config` reserved by Pydantic v2; using model_config to silence warnings
    model_config = {"protected_namespaces": ()}
    model: str
    input: str


def get_oracle() -> Oracle:
    if _ORACLE is None:
        raise RuntimeError("oracle not initialized; call create_app first")
    return _ORACLE


def create_app(oracle: Oracle) -> FastAPI:
    global _ORACLE
    _ORACLE = oracle
    app = FastAPI(title="VERITAS Oracle", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "ok": True,
            "pubkey": oracle.pubkey_hex,
            "current_epoch": oracle.current.number,
            "models": oracle.list_models(),
        }

    @app.get("/pubkey")
    def pubkey() -> dict[str, str]:
        return {"xonly_pubkey": oracle.pubkey_hex}

    @app.get("/models")
    def models() -> dict[str, Any]:
        return {"models": oracle.list_models()}

    @app.post("/infer")
    def infer(req: InferReq) -> dict[str, Any]:
        try:
            signed, evt = oracle.attest(req.model, req.input)
        except KeyError as e:
            raise HTTPException(404, str(e))
        return {
            "attestation": signed.attestation.to_payload(),
            "sig": signed.sig,
            "nostr": evt.to_dict(),
            "digest_hex": attestation_digest(signed.attestation).hex(),
        }

    @app.post("/infer/premium")
    def infer_premium(
        req: InferReq,
        authorization: str | None = Header(default=None),
    ) -> Response:
        resource_id = f"premium:{req.model}"
        if authorization and authorize(
            _L402_SECRET, _LN,
            auth_header_value=authorization,
            resource_id=resource_id,
        ):
            try:
                signed, evt = oracle.attest(req.model, req.input)
            except KeyError as e:
                raise HTTPException(404, str(e))
            return JSONResponse({
                "attestation": signed.attestation.to_payload(),
                "sig": signed.sig,
                "nostr": evt.to_dict(),
            })
        # No / bad auth -> issue a challenge.
        chal = make_challenge(_L402_SECRET, _LN, resource_id=resource_id,
                              amount_msat=1000)
        return JSONResponse(
            {
                "error": "Payment Required",
                "challenge": {
                    "macaroon_token": chal.macaroon_token,
                    "invoice_bolt11": chal.invoice_bolt11,
                    "payment_hash": chal.payment_hash,
                    "demo_preimage_hint": "POST /demo/reveal/{payment_hash}",
                },
            },
            status_code=402,
            headers={"WWW-Authenticate": chal.header_value()},
        )

    @app.post("/demo/reveal/{payment_hash}")
    def demo_reveal(payment_hash: str) -> dict[str, str]:
        """DEMO ONLY: pretend to pay an invoice and reveal preimage.

        Real deployments REMOVE this endpoint.
        """
        try:
            preimage_hex = _LN.reveal_preimage(payment_hash)
        except KeyError:
            raise HTTPException(404, "unknown payment_hash")
        return {"preimage": preimage_hex}

    @app.post("/close-epoch")
    def close_epoch() -> dict[str, Any]:
        epoch = oracle.close_epoch()
        return {
            "epoch": epoch.number,
            "root": epoch.root_hex,
            "leaf_count": len(epoch.attestations),
            "checkpoint": (
                epoch.checkpoint_event.to_dict() if epoch.checkpoint_event else None
            ),
            "anchor": (
                {
                    "txid": epoch.anchor_tx.txid,
                    "raw_hex": epoch.anchor_tx.raw_hex,
                    "fee_sats": epoch.anchor_tx.fee_sats,
                    "op_return_hex": epoch.anchor_tx.op_return_payload.hex(),
                }
                if epoch.anchor_tx
                else None
            ),
        }

    @app.get("/epoch/{n}")
    def epoch_info(n: int) -> dict[str, Any]:
        e = oracle.get_epoch(n)
        if e is None:
            raise HTTPException(404, f"unknown epoch {n}")
        return {
            "number": e.number,
            "closed": e.closed,
            "leaf_count": len(e.attestations),
            "root": e.root_hex,
            "checkpoint": e.checkpoint_event.to_dict() if e.checkpoint_event else None,
            "anchor_txid": e.anchor_tx.txid if e.anchor_tx else None,
            "attestations": [
                {
                    "index": i,
                    "digest_hex": attestation_digest(sa.attestation).hex(),
                    "model": sa.attestation.model,
                    "output": sa.attestation.output,
                    "ts": sa.attestation.ts,
                }
                for i, sa in enumerate(e.attestations)
            ],
        }

    @app.get("/epoch/{n}/proof/{i}")
    def epoch_proof(n: int, i: int) -> dict[str, Any]:
        e = oracle.get_epoch(n)
        if e is None:
            raise HTTPException(404, f"unknown epoch {n}")
        if not e.closed:
            raise HTTPException(409, "epoch not closed yet")
        proof = oracle.inclusion_proof(n, i)
        if proof is None:
            raise HTTPException(404, "no such leaf")
        return {
            "leaf_hex": proof.leaf.hex(),
            "siblings_hex": [s.hex() for s in proof.siblings],
            "directions": proof.directions,
            "root_hex": proof.root.hex(),
        }

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> HTMLResponse:
        from .web import render_dashboard
        return HTMLResponse(render_dashboard(oracle))

    return app

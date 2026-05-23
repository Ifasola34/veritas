"""Inference models the oracle can serve.

For the prototype we ship a deterministic keyword sentiment model so the
demo and tests pass without internet access. The interface is a single
abstract method `infer(input_text) -> dict`; swapping in the user's
existing transformer-based sentiment agent or a Kronos forecast call is
one function.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Protocol


class OracleModel(Protocol):
    """Anything an oracle can register and run."""

    @property
    def model_id(self) -> str: ...
    def infer(self, input_text: str) -> dict[str, Any]: ...


def normalize_input(text: str) -> tuple[str, str]:
    """Whitespace-collapse, lowercase. Returns (normalized, sha256_hex)."""
    norm = re.sub(r"\s+", " ", text.strip().lower())
    digest = hashlib.sha256(norm.encode("utf-8")).hexdigest()
    return norm, digest


# ---------------------------------------------------------------------
# Deterministic sentiment model — no network, no NN, just for the demo.
# ---------------------------------------------------------------------

_POS_WORDS = {
    "bullish", "moon", "pump", "long", "rip", "breakout", "support",
    "buy", "accumulate", "strong", "rally", "green", "up", "gain",
    "outperform", "upgrade", "beat", "exceeds",
}
_NEG_WORDS = {
    "bearish", "dump", "short", "crash", "rug", "resistance", "sell",
    "weak", "red", "down", "loss", "underperform", "downgrade", "miss",
    "rejected", "fade", "rejected", "capitulation",
}


@dataclass
class KeywordSentimentModel:
    model_id: str = "veritas.sentiment.keyword.v1"

    def infer(self, input_text: str) -> dict[str, Any]:
        norm, _ = normalize_input(input_text)
        tokens = re.findall(r"[a-z']+", norm)
        pos = sum(1 for t in tokens if t in _POS_WORDS)
        neg = sum(1 for t in tokens if t in _NEG_WORDS)
        total = pos + neg
        if total == 0:
            score = 0.0
            label = "neutral"
        else:
            score = (pos - neg) / total
            label = "bullish" if score > 0.2 else "bearish" if score < -0.2 else "neutral"
        return {
            "label": label,
            "score": round(score, 4),
            "pos_hits": pos,
            "neg_hits": neg,
            "token_count": len(tokens),
        }


# ---------------------------------------------------------------------
# A second toy model so the multi-model demo is honest.
# ---------------------------------------------------------------------

@dataclass
class MempoolPressureModel:
    """Deterministic stub that maps an input describing mempool state
    into a 'fee pressure' band. In production this would be wired to
    a real mempool-watching daemon.
    """

    model_id: str = "veritas.mempool.pressure.v1"

    def infer(self, input_text: str) -> dict[str, Any]:
        # The input is expected to be a JSON-like 'sat/vB ~ N pending Y'.
        # We just extract the first integer as a fee proxy.
        m = re.search(r"\d+", input_text)
        sat_vb = int(m.group(0)) if m else 1
        band = (
            "low" if sat_vb < 10
            else "moderate" if sat_vb < 50
            else "high" if sat_vb < 200
            else "extreme"
        )
        return {"sat_vb": sat_vb, "band": band}


REGISTRY: dict[str, OracleModel] = {
    KeywordSentimentModel().model_id: KeywordSentimentModel(),
    MempoolPressureModel().model_id: MempoolPressureModel(),
}

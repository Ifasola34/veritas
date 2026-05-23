"""Tiny self-contained HTML dashboard (no JS framework, no static files)."""

from __future__ import annotations

import html
import json

from .oracle import Oracle


def render_dashboard(oracle: Oracle) -> str:
    rows: list[str] = []
    epochs = list(oracle.past) + (
        [] if oracle.current.closed else [oracle.current]
    )
    for e in epochs[-10:][::-1]:
        rows.append(f"""
        <tr>
          <td>{e.number}</td>
          <td>{'closed' if e.closed else 'open'}</td>
          <td>{len(e.attestations)}</td>
          <td><code>{(e.root_hex or '—')[:24]}…</code></td>
          <td>{e.anchor_tx.txid[:16] + '…' if e.anchor_tx else '—'}</td>
        </tr>
        """)

    latest_atts = (
        oracle.current.attestations[-8:]
        if oracle.current.attestations else []
    )
    atts_rows: list[str] = []
    for sa in latest_atts:
        out = html.escape(json.dumps(sa.attestation.output))
        atts_rows.append(f"""
        <tr>
          <td>{sa.attestation.epoch}</td>
          <td><code>{sa.attestation.model}</code></td>
          <td>{out}</td>
          <td><code>{sa.attestation.input_hash[:12]}…</code></td>
        </tr>
        """)

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8" />
<title>VERITAS Oracle</title>
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "SF Mono", Monaco, monospace;
    background: #0b0d10; color: #d7dadc; max-width: 1080px; margin: 2em auto;
    padding: 0 1em;
  }}
  h1 {{ color: #f7931a; letter-spacing: -0.5px; }}
  h2 {{ color: #8ab4f8; border-bottom: 1px solid #2a2d31; padding-bottom: .3em; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1em 0; }}
  th, td {{ padding: .5em .8em; text-align: left;
           border-bottom: 1px solid #1b1f23; }}
  th {{ color: #aab; font-weight: 600; }}
  code {{ background: #14181c; padding: 1px 5px; border-radius: 3px;
          color: #9ce5a3; }}
  .kv {{ display: grid; grid-template-columns: 200px 1fr; gap: .3em 1em; }}
  .pill {{ display: inline-block; padding: 2px 8px; border-radius: 10px;
           background: #14181c; color: #f7931a; font-size: 12px; }}
  form {{ background: #14181c; padding: 1em; border-radius: 6px;
          margin: 1em 0; }}
  input, select, textarea {{ width: 100%; background: #0b0d10; color: #d7dadc;
        border: 1px solid #2a2d31; padding: .5em; border-radius: 4px;
        font-family: inherit; }}
  button {{ background: #f7931a; color: #0b0d10; border: 0;
            padding: .6em 1.2em; border-radius: 4px; cursor: pointer;
            font-weight: 600; }}
</style>
</head><body>
<h1>VERITAS <span class="pill">v0.1.0</span></h1>
<p>Bitcoin-anchored, Schnorr-signed AI inference attestations published on Nostr,
paid in Lightning sats. <a href="/health" style="color:#8ab4f8">/health</a> ·
<a href="/models" style="color:#8ab4f8">/models</a></p>

<h2>Oracle identity</h2>
<div class="kv">
  <div>x-only pubkey</div><div><code>{oracle.pubkey_hex}</code></div>
  <div>current epoch</div><div>{oracle.current.number}</div>
  <div>models registered</div>
  <div>{', '.join(f'<code>{m}</code>' for m in oracle.list_models())}</div>
</div>

<h2>Recent epochs</h2>
<table>
  <tr><th>#</th><th>state</th><th>leaves</th><th>root</th><th>anchor txid</th></tr>
  {''.join(rows) if rows else '<tr><td colspan=5><em>no closed epochs yet</em></td></tr>'}
</table>

<h2>Recent attestations (current epoch)</h2>
<table>
  <tr><th>epoch</th><th>model</th><th>output</th><th>input hash</th></tr>
  {''.join(atts_rows) if atts_rows else '<tr><td colspan=4><em>no attestations yet</em></td></tr>'}
</table>

<h2>Try it</h2>
<form action="/infer" method="post" enctype="application/json">
  <p>POST /infer with body <code>{{"model": "...", "input": "..."}}</code></p>
  <p>Example via curl:</p>
  <pre>curl -s -X POST http://localhost:8000/infer \\
  -H 'content-type: application/json' \\
  -d '{{"model":"veritas.sentiment.keyword.v1","input":"bullish breakout strong"}}' | jq</pre>
</form>

<p style="color: #888; margin-top: 3em; font-size: 12px;">
VERITAS is a research prototype. Anchor outputs are signet by default;
Lightning is mocked. See <code>docs/CREATIVITY.md</code>.
</p>
</body></html>"""

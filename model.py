"""
model.py — adapter to the local LLM (llama.cpp llama-server on the VM).

The VM runs an OpenAI-compatible server at http://<host>:8090/v1 with the
`bonsai2` model loaded (no auth). This module is a thin client that:

  - POSTs /v1/chat/completions with a system prompt + a signals payload
  - returns the plain-language explanation (str)
  - falls back to a deterministic "no model" explanation if the call fails
    (so triage is always usable, offline, on a homelab where the VM is down)

Config via env:
  PCAP_TRIAGE_MODEL_HOST  default http://100.86.193.106:8090/v1
  PCAP_TRIAGE_MODEL       default bonsai2
  PCAP_TRIAGE_TIMEOUT     seconds, default 300 (48 tok/s * 65k context can be slow)
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
import urllib.error

DEFAULT_HOST = "http://100.86.193.106:8090/v1"
DEFAULT_MODEL = "bonsai2"
DEFAULT_TIMEOUT = 300

SYSTEM_PROMPT = (
    "You are a network security analyst triaging a packet capture. "
    "You are given a list of network flows with deterministic signals "
    "(beaconing, entropy, rare ports, TLS fingerprint, SNI, domains). "
    "For EACH flow, in 1-2 plain-English sentences, state: (1) what it is "
    "doing, (2) the most likely threat (C2 beacon / exfiltration / benign / "
    "other) with your reasoning, (3) one concrete recommended action. "
    "Be concise. Do not invent data not present in the signals. "
    "If a signal is inconclusive, say so explicitly rather than guessing."
)


def _call_model(host, model, user_signals_text, timeout):
    payload = {
        "model": model,
        "temperature": 0.2,
        "max_tokens": 3000,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_signals_text},
        ],
    }
    req = urllib.request.Request(
        host.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode())
    return body["choices"][0]["message"]["content"].strip()


def explain(signals: list) -> str:
    """
    Ask the local model to explain a list of flow signals in plain English.
    Returns the model's text. On any failure, returns a deterministic
    fallback explanation so the tool is always usable offline.
    """
    host = os.environ.get("PCAP_TRIAGE_MODEL_HOST", DEFAULT_HOST)
    model = os.environ.get("PCAP_TRIAGE_MODEL", DEFAULT_MODEL)
    timeout = float(os.environ.get("PCAP_TRIAGE_TIMEOUT", DEFAULT_TIMEOUT))
    if not signals:
        return "No flows found in the capture."

    user_signals_text = "Flow signals (JSON):\n" + json.dumps(signals, indent=2)
    try:
        return _call_model(host, model, user_signals_text, timeout)
    except Exception as e:
        return _fallback_explain(signals, error=e)


def _fallback_explain(signals, error) -> str:
    lines = []
    if error is not None:
        lines.append(f"[model unavailable ({error}); using deterministic notes]")
    lines.append("")
    for s in signals:
        f = s["flow"]
        notes = []
        if s["beacon_score"] >= 0.4:
            notes.append(f"beaconing (mean IAT {s['mean_iat_s']}s, std {s['iat_std_s']}s, score {s['beacon_score']})")
        if s["high_entropy"]:
            notes.append(f"high-entropy payload (mean {s['mean_entropy']})")
        if s["suspicious_port"]:
            notes.append(f"suspicious dst port {f['dst_port']}")
        elif s["rare_dst_port"]:
            notes.append(f"non-standard dst port {f['dst_port']}")
        if s["has_tls"] and s["sni"]:
            notes.append(f"TLS SNI={s['sni']} JA3={s['ja3'][:16]}...")
        if s["rare_domains"]:
            notes.append(f"uncommon domains: {', '.join(s['rare_domains'])}")
        if not notes:
            notes.append("no strong threat indicators (likely benign)")
        lines.append(f"- {f['src']}:{f['src_port']} -> {f['dst']}:{f['dst_port']} ({f['proto']}, "
                     f"{f['packets']} pkts, {f['bytes']} B): " + "; ".join(notes))
    lines.append("")
    lines.append("Recommended: review flagged flows; block/beacon C2 candidates at the firewall.")
    return "\n".join(lines)

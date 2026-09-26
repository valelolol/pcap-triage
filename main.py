"""
main.py — CLI entrypoint for pcap-triage.

Usage:
    python main.py capture.pcap
    python main.py capture.pcap --no-model        # deterministic notes only
    python main.py capture.pcap --json            # print signals as JSON
    python main.py capture.pcap --top 10          # only top-N flows by packet count
"""
from __future__ import annotations

import argparse
import json
import sys
import time

import pcap_reader
import triage
import model


def triage_capture(path: str, use_model: bool = True, top_n: int | None = None):
    extractor = triage.FlowExtractor()
    start = time.monotonic()
    n = 0
    with open(path, "rb") as fh:
        for ts_ns, raw in pcap_reader.iter_records(path):
            extractor.ingest(ts_ns, raw)
            n += 1
    signals = triage.all_signals(extractor)
    elapsed = time.monotonic() - start
    if top_n:
        signals = sorted(signals, key=lambda s: s["flow"]["packets"], reverse=True)[:top_n]
    return signals, n, elapsed


def render(signals, n, elapsed, use_model):
    out = []
    out.append("=" * 64)
    out.append("pcap-triage  —  autonomous network capture triage")
    out.append("=" * 64)
    out.append(f"capture: {n} packets parsed in {elapsed:.2f}s")
    out.append(f"flows: {len(signals)} distinct 5-tuple flows\n")
    if use_model:
        out.append("## Model analysis (local LLM)")
        out.append("-" * 64)
        out.append(model.explain(signals))
        out.append("")
    out.append("## Deterministic signals")
    out.append("-" * 64)
    for s in signals:
        f = s["flow"]
        flags = []
        if s["beacon_score"] >= 0.4:
            flags.append("BEACON")
        if s["high_entropy"]:
            flags.append("HIGH_ENTROPY")
        if s["suspicious_port"]:
            flags.append("SUSP_PORT")
        elif s["rare_dst_port"]:
            flags.append("RARE_PORT")
        if s["has_tls"]:
            flags.append("TLS")
        if s["rare_domains"]:
            flags.append("RARE_DOM")
        flag_str = f"[{', '.join(flags)}]" if flags else "[none]"
        out.append(f"{flag_str} {f['src']}:{f['src_port']} -> {f['dst']}:{f['dst_port']} "
                   f"({f['proto']}, {f['packets']} pkts, {f['bytes']} B)")
        out.append(f"    IAT={s['mean_iat_s']}s/{s['iat_std_s']}s "
                   f"entropy={s['mean_entropy']} beacon={s['beacon_score']}")
        if s["sni"]:
            out.append(f"    SNI={s['sni']}")
        if s["ja3"]:
            out.append(f"    JA3={s['ja3']}")
        if s["domains"]:
            out.append(f"    domains={', '.join(s['domains'][:5])}{'...' if len(s['domains'])>5 else ''}")
        out.append("")
    out.append("=" * 64)
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Autonomous network capture triage (local LLM).")
    ap.add_argument("pcap", help="path to pcap or pcapng capture")
    ap.add_argument("--no-model", action="store_true",
                    help="skip the local model; print deterministic notes only")
    ap.add_argument("--json", action="store_true", help="print signals as JSON only")
    ap.add_argument("--top", type=int, default=None,
                    help="only show top-N flows by packet count")
    args = ap.parse_args()

    signals, n, elapsed = triage_capture(args.pcap,
                                         use_model=not args.no_model,
                                         top_n=args.top)
    if args.json:
        print(json.dumps({"packets": n, "signals": signals}, indent=2))
    else:
        print(render(signals, n, elapsed, use_model=not args.no_model))


if __name__ == "__main__":
    main()

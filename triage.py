"""
triage.py — flow extraction and deterministic signal computation.

Reads (ts_ns, raw_bytes) records from the pcap, parses each into a packet
dict, groups them into 5-tuple flows (src_ip,src_port,dst_ip,dst_port), and
per flow computes the deterministic signals the local model reasons about:

  beaconing:        mean + std inter-arrival interval (periodic = C2 beacon)
  entropy:          Shannon entropy of the payload (random = exfil/encrypted C2)
  rare_port:        destination on a non-standard port (common C2 ports flagged)
  tls_fingerprint:  JA3 client hash + SNI (cert/infra correlation)
  dns:              domains seen in DNS queries (rare / lookalike detection)
  payload_stats:    packet count, byte count, symmetry (symmetric = likely benign)

The output per flow is a plain dict "signals". A separate `signals.py`
threshold module maps signals -> a per-signal risk note, and `model.py`
asks the local model to turn all signals into one plain-English incident
summary. This separation is deliberate: the deterministic layer is
reproducible (no model needed, fully unit-testable) and the model layer is
a swappable explainer.
"""
from __future__ import annotations

import re
import statistics
from collections import defaultdict
from dataclasses import dataclass, field

import pkt

# --- common well-known ports (for rare-port detection) ------------------
WELL_KNOWN = {
    21, 22, 23, 25, 26, 27, 53, 80, 81, 110, 143, 443, 546,
    993, 995, 123, 465, 636, 672, 993, 995, 3389, 3306, 5432,
    8080, 8000, 8443,
}

# Ports commonly abused for C2 / exfil. Kept disjoint from WELL_KNOWN
# on purpose: a standard port (443/8080/8000/8443) is NOT suspicious by
# itself, so a standard HTTPS flow must never trip the "suspicious port"
# flag. These are non-standard ports frequently seen in C2 / exfil tooling.
SUSPICIOUS_PORTS = {
    135, 5438, 445, 1337, 1234, 9000, 12345,
    4444, 5555, 6666, 7777, 8888, 9999, 2222, 3333,
    13333, 10000, 10001, 10002, 10003, 10004,
}

# --- DNS / SNI domain detection ----------------------------------------

# A "domain" for our purposes: hostname tokens in the payload (lowercase).
_DOMAIN_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}"
)

# Common benign TLDs / prefixes (not a blocklist, just a *reduce-noise* heuristic)
_BENIGN_PREFIXES = (
    "google.", "facebook.", "whatsapp.", "microsoft.", "apple.", "amazon.",
    "youtube.", "github.", "api.", "static.", "cdn.", "cloudflare.", "ad.",
    "doubleclick.", "facebook.", "googleapis.", "gstatic.", "gsp.",
)

@dataclass
class Flow:
    key: tuple  # (src_ip, src_port, dst_ip, dst_port)
    ts: list = field(default_factory=list)
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    proto: str = "unknown"
    total_bytes: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0
    packets: int = 0
    entropy: float = 0.0
    ja3: str = ""
    sni: str = ""
    domains: set = field(default_factory=set)
    # per-packet entropy (to compute the mean across the flow, not a single max)
    entropies: list = field(default_factory=list)

    def add_packet(self, ts_ns, src_mac, dst_mac, src_ip, dst_ip,
                   src_port, dst_port, proto, payload, is_client_tls,
                   ja3, sni, entropy):
        self.ts.append(ts_ns)
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.packets += 1
        # tx = from src -> dst (our vantage sees src side as "client" typically)
        self.tx_bytes += len(payload)
        self.total_bytes += len(payload)
        self.entropies.append(entropy)
        if entropy > self.entropy:
            self.entropy = entropy
        if ja3:
            self.ja3 = ja3
        if sni and sni not in self.domains:
            self.domains.add(sni)
            self.sni = sni

    @property
    def mean_entropy(self):
        return statistics.mean(self.entropies) if self.entropies else 0.0


class FlowExtractor:
    def __init__(self):
        self.flows: dict = {}

    def ingest(self, ts_ns, raw):
        eth = pkt.parse_ethernet(raw)
        if eth is None or eth["ethertype"] != pkt.ETHERTYPE_IPV4:
            return
        ip = pkt.parse_ipv4(eth["payload"])
        if ip is None:
            return
        src_ip, dst_ip = ip["src_ip"], ip["dst_ip"]
        proto = ip["payload"]
        src_port = dst_port = 0
        payload = b""
        tls = {"ja3": "", "ja3s": "", "sni": None, "is_client": False}
        if ip["proto"] == pkt.IP_PROTO_TCP:
            t = pkt.parse_tcp(ip["payload"])
            if t:
                src_port, dst_port = t["src_port"], t["dst_port"]
                payload = t["data"]
                # detect TLS client hello in TCP data
                ch = pkt._find_client_hello(payload)
                if ch is not None:
                    tls = pkt.parse_tls(payload)
                    tls["is_client"] = True
        elif ip["proto"] == pkt.IP_PROTO_UDP:
            u = pkt.parse_udp(ip["payload"])
            if u:
                src_port, dst_port = u["src_port"], u["dst_port"]
                payload = u["data"]
        # DNS: look for a DNS query in the UDP payload (port 53)
        domains = set()
        if dst_port == 53 or src_port == 53:
            domains = _extract_dns_domains(payload)
        elif payload:
            domains = _extract_domains(payload)

        key = (src_ip, src_port, dst_ip, dst_port)
        if key not in self.flows:
            self.flows[key] = Flow(key=key)
        f = self.flows[key]
        f.add_packet(ts_ns, eth["src_mac"], eth["dst_mac"], src_ip, dst_ip,
                     src_port, dst_port,
                     "tcp" if ip["proto"] == 6 else "udp" if ip["proto"] == 17 else "other",
                     payload, tls["is_client"], tls["ja3"], tls["sni"],
                     pkt.shannon_entropy(payload))
        f.domains.update(domains)

    def flows_dict(self):
        return {k: f for k, f in self.flows.items()}


def _extract_dns_domains(payload: bytes) -> set:
    """Extract domains from a DNS query/answer packet.
    DNS names are length-prefixed; we parse the query section."""
    domains = set()
    try:
        # DNS header: 12 bytes; then QNAME (variable), QTYPE(2), QCLASS(2), ...
        if len(payload) < 12:
            return domains
        # parse first question
        pos = 12
        qnames = []
        for _ in range(1):
            if pos + 1 > len(payload):
                break
            label_len = payload[pos]
            if label_len == 0:
                break
            if label_len <= 63:
                name = payload[pos + 1 : pos + 1 + label_len]
                qnames.append(name)
            pos += 1 + label_len
        # Also try a loose regex on the whole packet as a fallback
        text = payload.decode("ascii", "ignore")
        for m in _DOMAIN_RE.finditer(text):
            domains.add(m.group(0))
        for qn in qnames:
            # qn is a raw byte label; decode and join
            try:
                dom = ".".join(qnames).lower()
                if len(dom) >= 3:
                    domains.add(dom)
            except Exception:
                pass
    except Exception:
        pass
    return domains


def _extract_domains(payload: bytes) -> set:
    """Loose domain extraction from a binary payload (TLS SNI, HTTP, etc.)."""
    domains = set()
    try:
        text = payload.decode("ascii", "ignore")
        for m in _DOMAIN_RE.finditer(text):
            d = m.group(0).lower()
            domains.add(d)
    except Exception:
        pass
    return domains


# --- per-flow signal computation ----------------------------------------

def compute_signals(f: Flow) -> dict:
    """Turn a Flow into the deterministic signals dict."""
    ts = [t / 1e9 for t in f.ts]  # seconds
    if len(ts) < 2:
        mean_iat = 0.0
        iat_std = 0.0
    else:
        iats = [b - a for a, b in zip(ts, ts[1:])]
        mean_iat = statistics.mean(iats)
        iat_std = statistics.stdev(iats) if len(iats) > 1 else 0.0

    # beaconing: very regular intervals (low coefficient of variation) with
    # enough samples. Real C2 beacons are precisely timed (low jitter); human
    # web traffic is irregular (high jitter) and therefore does NOT trigger.
    beacon_score = 0.0
    if len(ts) >= 3 and mean_iat > 0:
        cv = iat_std / mean_iat
        if cv < 0.15:
            beacon_score = 0.9
        elif cv < 0.3:
            beacon_score = 0.5
        elif cv < 0.5:
            beacon_score = 0.25
        # cv >= 0.5 -> irregular -> not beacon-like

    # rare-port flag
    rare_port = dst_is_rare(f.dst_port) if f.proto == "tcp" else False
    suspicious_port = f.dst_port in SUSPICIOUS_PORTS

    # entropy flag
    ent = f.mean_entropy if f.entropies else 0.0
    high_entropy = ent > pkt.ENTROPY_RANDOM

    # TLS fingerprint / SNI
    has_tls = bool(f.ja3) or bool(f.sni)
    sni_list = sorted({f.sni} - {None}) if f.sni else []

    # domains (rare / lookalike)
    dom_list = sorted(f.domains)
    rare_domains = _rare_domains(dom_list)

    # symmetry: how much data in each direction (we only track src->dst here)
    symmetry = 0.0  # not computable from single-direction; leave as 0

    return {
        "flow": {
            "src": f.src_ip, "dst": f.dst_ip,
            "src_port": f.src_port, "dst_port": f.dst_port,
            "proto": f.proto,
            "packets": f.packets,
            "bytes": f.tx_bytes,
            "src_mac": f.src_mac,
            "dst_mac": f.dst_mac,
        },
        "mean_iat_s": round(mean_iat, 3),
        "iat_std_s": round(iat_std, 3),
        "beacon_score": round(beacon_score, 2),
        "mean_entropy": round(ent, 2),
        "high_entropy": high_entropy,
        "rare_dst_port": rare_port,
        "suspicious_port": suspicious_port,
        "has_tls": has_tls,
        "ja3": f.ja3,
        "sni": f.sni,
        "domains": dom_list,
        "rare_domains": rare_domains,
        "symmetry": symmetry,
    }


def dst_is_rare(port: int) -> bool:
    return port > 0 and port not in WELL_KNOWN


def _rare_domains(domains):
    """Flag domains not starting with common benign prefixes (heuristic)."""
    rare = []
    for d in domains:
        if not any(d.startswith(p) for p in _BENIGN_PREFIXES):
            rare.append(d)
    return rare


def all_signals(extractor: FlowExtractor) -> list:
    return [compute_signals(f) for f in extractor.flows_dict().values()]

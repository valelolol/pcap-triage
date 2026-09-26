"""
pkt.py — zero-dependency packet parsing for pcap-triage.

Parses Ethernet -> IPv4 -> TCP/UDP payloads into structured dicts, plus
TLS client fingerprinting (JA3/JA3S) and SNI extraction. Pure stdlib so the
project runs on Windows, Kali, or the model VM with zero PyPI deps.

The feature layer (in triage.py) groups frames into 5-tuple flows and derives
the deterministic signals the local model reasons about:
  - beaconing / periodicity   (inter-arrival jitter + mean interval)
  - entropy                  (Shannon entropy of payload bytes)
  - rare / non-standard ports
  - JA3 / JA3S client TLS fingerprint
  - SNI extraction
  - DNS query / response domains
"""
from __future__ import annotations

import hashlib
import struct
from collections import defaultdict


# --- EtherType / proto constants ---------------------------------------
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806

IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_ICMP = 1

# --- TCP flags ----------------------------------------------------------
TCP_SYN = 0x02
TCP_FIN = 0x16
TCP_RST = 0x10
TCP_ACK = 0x18
TCP_PSH = 0x08

# --- entropy thresholds (bits/byte) ------------------------------------
# Shannon entropy in bits/byte; 8.0 is max (uniform random).
ENTROPY_RANDOM = 7.0
ENTROPY_LOW = 5.0


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte. 8.0 is max (uniform random)."""
    if not data:
        return 0.0
    import math
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


# --- Ether / IPv4 -------------------------------------------------------

def parse_ethernet(frame: bytes) -> dict | None:
    if len(frame) < 14:
        return None
    return {
        "layer": "ethernet",
        "src_mac": "=".join(f"{b:02x}" for b in frame[6:12]),
        "dst_mac": "=".join(f"{b:02x}" for b in frame[0:6]),
        "ethertype": struct.unpack("!H", frame[12:14])[0],
        "payload": frame[14:],
    }


def parse_ipv4(frame: bytes) -> dict | None:
    if len(frame) < 20 or frame[0] >> 4 != 4:
        return None
    ihl = (frame[0] & 0x0F) * 4
    total_len = struct.unpack("!H", frame[2:4])[0]
    proto = frame[9]
    src = ".".join(str(b) for b in list(frame[12:16]))
    dst = ".".join(str(b) for b in list(frame[16:20]))
    payload = frame[ihl:]
    return {
        "layer": "ipv4",
        "proto": proto,
        "src_ip": src,
        "dst_ip": dst,
        "ttl": frame[7],
        "payload": payload,
    }


# --- TCP / UDP ---------------------------------------------------------

def parse_tcp(payload: bytes) -> dict | None:
    if len(payload) < 20:
        return None
    return {
        "src_port": struct.unpack("!H", payload[0:2])[0],
        "dst_port": struct.unpack("!H", payload[2:4])[0],
        "flags": struct.unpack("!B", payload[13:14])[0],
        "data": payload[20:],
    }


def parse_udp(payload: bytes) -> dict | None:
    if len(payload) < 8:
        return None
    return {
        "src_port": struct.unpack("!H", payload[0:2])[0],
        "dst_port": struct.unpack("!H", payload[2:4])[0],
        "data": payload[8:],
    }


# --- TLS: JA3 / JA3S / SNI -------------------------------------------
#
# JA3 (https://github.com/armitage/ssl-sha1 / JA3 spec):
#   sha1( <min_version:4> <num_ciphers:2> <ciphers: 2N bytes>
#           <num_exts:2> <ext_types: 2M bytes> )
# where min_version is the client hello version, num_ciphers/num_exts are
# the count bytes (hex-2), and ciphers/ext_types are each hex-2.

def _ja3_raw(client_hello: bytes) -> str:
    """Build the JA3 raw string from a ClientHello (JA3 spec)."""
    # ClientHello:
    #   0  magic  0x16
    #   1  type  0x03 (Handshake)
    #   2:4  handshake length (big)
    #   4:6  client version (big)
    #   7    rand_len (16)
    #   8    rand (16 bytes)
    #   25   session_id_len (0)
    #   26   session_id
    #   26+  cipher_suite_list: num (1) + 2*num
    #   ...  extensions: total_len (2)
    pos = 4
    ver = (client_hello[pos] << 8) | client_hello[pos + 1]
    rand_len = client_hello[7]
    session_len = client_hello[7 + rand_len]
    pos = 7 + rand_len + 1 + session_len
    num_ciphers = client_hello[pos]
    pos += 1
    ciphers = []
    for _ in range(num_ciphers):
        ciphers.append(f"{client_hello[pos]:02x}{client_hello[pos + 1]:02x}")
        pos += 2
    num_ext = client_hello[pos]
    pos += 1
    exts = []
    for _ in range(num_ext):
        e_type, e_len = client_hello[pos], client_hello[pos + 1]
        exts.append(f"{e_type:02x}{e_len:02x}")
        pos += 2 + e_len
    return (f"{ver:04x}{num_ciphers:02x}"
            + "".join(ciphers)
            + f"{num_ext:02x}" + "".join(exts))


def extract_ja3(client_hello: bytes) -> str:
    """JA3 client fingerprint (128 hex chars)."""
    if len(client_hello) < 10 or client_hello[0] != 0x16:
        return ""
    try:
        raw = _ja3_raw(client_hello)
    except Exception:
        return ""
    return hashlib.sha1(raw.encode()).hexdigest()


def extract_ja3s(client_hello: bytes) -> str:
    """JA3S (server) — here we approximate with JA3 of the client hello since
    we only parse client traffic; full impl would parse the ServerHello.
    Kept for API symmetry."""
    return extract_ja3(client_hello)


def _find_client_hello(payload: bytes) -> bytes | None:
    """
    If `payload` is a TLS record, return the ClientHello inside it.
    Otherwise, if `payload` itself looks like a ClientHello (starts with 0x16 0x03), return it.
    """
    try:
        if len(payload) < 5:
            return None
        # TLS record: [16][22][len2][data]
        if payload[0] == 0x16 and payload[1] == 0x03:
            hand_len = struct.unpack("!H", payload[4:6])[0]
            ch = payload[5:5 + hand_len]
            return ch
        # Bare ClientHello: magic 0x16 0x03 handshake
        if payload[0] == 0x16 and payload[1] == 0x03:
            return payload
    except Exception:
        return None
    return None


def extract_sni(client_hello: bytes) -> str | None:
    """Extract SNI from a raw ClientHello."""
    try:
        if len(client_hello) < 10:
            return None
        pos = 4
        ver = (client_hello[pos] << 8) | client_hello[pos + 1]
        rand_len = client_hello[7]
        session_len = client_hello[7 + rand_len]
        pos = 7 + rand_len + 1 + session_len
        num_ciphers = client_hello[pos]
        pos += 1
        pos += num_ciphers * 2
        if pos + 1 >= len(client_hello):
            return None
        ext_len = struct.unpack("!H", client_hello[pos:pos + 2])[0]
        pos += 2
        end = pos + ext_len
        while pos < end:
            e_type = client_hello[pos]
            e_len = client_hello[pos + 1]
            pos += 2
            if e_type == 0x00:  # ServerName
                if pos + 4 < len(client_hello) + e_len:
                    inner_len = client_hello[pos]
                    if inner_len >= 1:
                        sni_type = client_hello[pos + 1]
                        if sni_type == 0:
                            name_len = struct.unpack("!H", client_hello[pos + 2:pos + 4])[0]
                            return client_hello[pos + 4:pos + 4 + name_len].decode("ascii", "ignore")
            pos += e_len
        return None
    except Exception:
        return None


def parse_tls(payload: bytes) -> dict:
    """Parse a TLS payload, returning ja3, ja3s, sni, is_client."""
    ch = _find_client_hello(payload)
    if ch is None:
        return {"ja3": "", "ja3s": "", "sni": None, "is_client": False}
    ja3 = extract_ja3(ch)
    sni = extract_sni(ch)
    return {"ja3": ja3, "ja3s": ja3, "sni": sni, "is_client": True}

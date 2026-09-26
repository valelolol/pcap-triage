"""
pcap_writer.py — minimal classic-pcap (v2.0) writer, little-endian.

Used by the test harness to synthesize captures with known ground truth
(a periodic C2 beacon, a high-entropy exfil, benign traffic) so we can
measure the signal extractor without depending on real captures.
"""
from __future__ import annotations

import struct


def write_classic_pcap(path, records, linktype=1):
    """
    records: list of (ts_ns, raw_bytes)
    """
    magic = 0xa1b2c3d4
    with open(path, "wb") as fh:
        # global header (24 bytes): magic(4) vermaj(2) vermin(2) thiszone(4)
        #                          snaplen(4) network(2)
        fh.write(struct.pack("<IHHIIH", magic, 2, 4, 0, 65535, linktype))
        for ts_ns, raw in records:
            ts_sec = ts_ns // 1_000_000_000
            ts_nsec = ts_ns % 1_000_000_000
            fh.write(struct.pack("<IIII", ts_sec, ts_nsec, len(raw), len(raw)))
            fh.write(raw)
    return path


# --- frame builders -----------------------------------------------------

def ethernet(src_mac, dst_mac, ethertype, payload):
    return struct.pack("!6s6sH", src_mac, dst_mac, ethertype) + payload


def ip4(src_ip, dst_ip, proto, ttl=64):
    """Build an IPv4 header + payload (dummy checksums; parser only reads fields)."""
    # pseudo: ihl=5, version=4, len=0 (set later), proto, ttl
    hdr = bytearray(20)
    hdr[0] = 0x45
    hdr[9] = proto
    hdr[7] = ttl
    src = bytes(int(p) for p in src_ip.split("."))
    dst = bytes(int(p) for p in dst_ip.split("."))
    hdr[12:16] = src
    hdr[16:20] = dst
    return bytes(hdr)


def tcp(src_port, dst_port, flags, data):
    hdr = bytearray(20)
    hdr[0:2] = struct.pack("!H", src_port)
    hdr[2:4] = struct.pack("!H", dst_port)
    hdr[12:14] = struct.pack("!H", 0)  # seq
    hdr[14:16] = struct.pack("!H", min(65535, len(data)))
    hdr[13] = flags
    return bytes(hdr) + data


def udp(src_port, dst_port, data):
    hdr = struct.pack("!HHHH", src_port, dst_port, min(65535, len(data) + 8), 0)
    return bytes(hdr) + data


# --- ground-truth builders --------------------------------------------------

def make_c2_beacon(n_beacons=20, period_s=45.0, jitter=0.0,
                   payload=b"\x9c\x3d\xf7\x8a\x00\x42\xbe\x77",
                   src="10.0.0.9", dst="185.220.101.43",
                   src_port=45220, dst_port=4444,
                   ts_start=0):
    """Periodic TLS-like C2 beacon on a suspicious port. High entropy payload."""
    records = []
    t = ts_start
    src_mac = bytes(0x01) * 6
    dst_mac = bytes(0x02) * 6
    for i in range(n_beacons):
        payload_bytes = payload + bytes([i])
        l4 = tcp(src_port, dst_port, 0x02 if i == 0 else 0x03, payload_bytes)
        ip = ip4(src, dst, 6, ttl=64)
        frame = ethernet(src_mac, dst_mac, 0x0800, ip + l4)
        records.append((t, frame))
        t += int(period_s * 1e9)
    return records


def make_exfil(n_packs=15, period_s=0.5,
               src="10.0.0.14", dst="209.12.23.111",
               src_port=51300, dst_port=80,
               ts_start=0):
    """High-entropy bulk POST to port 80 (exfil via HTTPS)."""
    import os
    records = []
    t = ts_start
    src_mac = bytes(0x03) * 6
    dst_mac = bytes(0x04) * 6
    for i in range(n_packs):
        payload_bytes = os.urandom(256)
        l4 = tcp(src_port, dst_port, 0x03, payload_bytes)
        ip = ip4(src, dst, 6, ttl=64)
        frame = ethernet(src_mac, dst_mac, 0x0800, ip + l4)
        records.append((t, frame))
        t += int(period_s * 1e9)
    return records


def make_benign_web(n=8, src="10.0.0.14", dst="142.250.180.206",
                    src_port=51301, dst_port=443, ts_start=0):
    """Benign HTTPS to a well-known IP on port 443 (low entropy, standard
    port). Intervals are irregular (real human web traffic) so the beacon
    detector should NOT flag this."""
    # irregular, human-like intervals (s) — clearly non-beacon
    intervals = [5, 35, 8, 40, 6, 38, 9, 32, 12, 44]
    records = []
    t = ts_start
    src_mac = bytes(0x05) * 6
    dst_mac = bytes(0x06) * 6
    for i in range(n):
        payload_bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        l4 = tcp(src_port, dst_port, 0x03, payload_bytes)
        ip = ip4(src, dst, 6, ttl=64)
        frame = ethernet(src_mac, dst_mac, 0x0800, ip + l4)
        records.append((t, frame))
        t += int(intervals[i % len(intervals)] * 1e9)
    return records


def make_demo_combined(n_beacons=20, n_exfil=15, n_benign=8):
    """Merge the three ground-truth builders into one combined capture:
    a C2 beacon (4444), a high-entropy exfil (80), and benign web (443).
    This is the capture shown in the README demo and the `demo.gif`."""
    return (make_c2_beacon(n_beacons)
            + make_exfil(n_exfil)
            + make_benign_web(n_benign))


if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    mode = next((a for a in args if a.startswith("--")), None)
    path = next((a for a in args if not a.startswith("--")), "synthetic.pcap")
    recs = make_demo_combined() if mode == "--combined" else make_c2_beacon()
    write_classic_pcap(path, recs)
    print(f"wrote {path} ({len(recs)} packets)")

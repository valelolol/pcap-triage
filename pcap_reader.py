"""
pcap_reader.py — zero-dependency reader for pcap / pcapng capture files.

Yields records as (timestamp_ns, raw_bytes, linklayer_type) tuples.

Supports:
  - classic pcap (dapper) little- and big-endian global headers
  - pcapng (global header, interface-link-type, data blocks, no data blocks)

Keeps stdlib-only on purpose: the whole project ships with zero PyPI deps
so it runs anywhere the user's homelab runs (Windows, Kali, the VM).
"""
from __future__ import annotations

import struct

# LinkLayerType 1 = DATALINK_EN10/EN10 (Ethernet) — the common case for pcaps.
LINKTYPE_EN10 = 1
LINKTYPE_ETH = 1


class PcapFile:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as fh:
            self._buf = fh.read()
        self._init()

    def _init(self):
        data = self._buf
        magic = struct.unpack("<I", data[:4])[0]
        # pcapng magic is 0x0a90d9a. Dapper pcap magics: 0xa1b2c3d4 (LE) / 0xd4c3b2a1 (BE)
        if magic in (0x0a90d9a,):
            self._parse_pcapng(data)
        elif magic == 0xa1b2c3d4:
            self._parse_classic(data, LE=True)
        elif magic == 0xd4c3b2a1:
            self._parse_classic(data, LE=False)
        else:
            raise ValueError(f"unrecognised capture magic 0x{magic:08x}: {self.path!r}")

    def _parse_classic(self, data, LE):
        endian = "<" if LE else ">"
        self.records = []
        # global header: magic(4) vermaj(2) vermin(2) thiszone(4) snaplen(4) network(2)
        # => header is 18 bytes total; the part after magic is 14 bytes.
        _vermaj, _vermin, _thiszone, snaplen, network = \
            struct.unpack(endian + "HHiIH", data[4:18])
        offset = 18
        while offset + 16 <= len(data):
            ts_sec, ts_nsec, inclen, origlen = struct.unpack(endian + "IIII", data[offset:offset + 16])
            payload = data[offset + 16 : offset + 16 + inclen]
            self.records.append((ts_sec * 1_000_000_000 + ts_nsec, payload, network))
            offset += 16 + inclen

    def _parse_pcapng(self, data):
        self.records = []
        # global header: magic(4) ver(4) res(4) thiszone(8) numinterfaces(4) options(8)
        offset = 16
        ninterfaces = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4
        for _ in range(ninterfaces):
            # InterfaceTypeBlock: type(4) + len(4) + interface_data
            itype, ilen = struct.unpack("<II", data[offset:offset + 8])
            offset += 8 + ilen
        while offset + 8 <= len(data):
            blkt = struct.unpack("<I", data[offset:offset + 4])[0]
            blklen = struct.unpack("<I", data[offset + 4:offset + 8])[0]
            if blkt == 2 and blklen >= 16:
                # DataBlock: ts_sec(4) + ts_nsec(4) + data_len(4) + data
                ts_sec, ts_nsec, data_len = struct.unpack("<III", data[offset + 8 : offset + 20])
                self.records.append(
                    (ts_sec * 1_000_000_000 + ts_nsec,
                     data[offset + 20 : offset + 20 + data_len], LINKTYPE_EN10)
                )
            offset += 8 + blklen
            # (we ignore non-data blocks here; a real reader would track iface)

    def iter_records(self):
        """Yield (ts_ns, bytes) pairs."""
        for ts, raw, _net in self.records:
            yield ts, raw

    def __len__(self):
        return len(self.records)


def iter_records(path):
    """Generator convenience: (ts_ns, bytes) pairs. Module-level alias."""
    return PcapFile(path).iter_records()


def iter_packets(path):
    """Alias of iter_records for backward compat."""
    return iter_records(path)

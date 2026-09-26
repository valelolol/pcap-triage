"""
tests/test_triage.py — unit + integration tests for the signal extractor.

Ground-truth: synthetic captures with known properties (beacon, exfil, benign).
Asserts the deterministic signals fire as expected. No network / model required.
"""
import pytest
import pcap_writer
import pcap_reader
import triage


@pytest.fixture
def c2_pcap(tmp_path):
    recs = pcap_writer.make_c2_beacon(n_beacons=20, period_s=45.0)
    p = tmp_path / "c2.pcap"
    pcap_writer.write_classic_pcap(p, recs)
    return p


@pytest.fixture
def exfil_pcap(tmp_path):
    recs = pcap_writer.make_exfil(n_packs=15)
    p = tmp_path / "exfil.pcap"
    pcap_writer.write_classic_pcap(p, recs)
    return p


@pytest.fixture
def benign_pcap(tmp_path):
    recs = pcap_writer.make_benign_web()
    p = tmp_path / "benign.pcap"
    pcap_writer.write_classic_pcap(p, recs)
    return p


def extract(path):
    ex = triage.FlowExtractor()
    for ts, raw in pcap_reader.iter_records(path):
        ex.ingest(ts, raw)
    return triage.all_signals(ex)


def test_reader_roundtrip(c2_pcap):
    """pcap_reader must be able to read back what pcap_writer wrote."""
    recs = list(pcap_reader.iter_records(c2_pcap))
    assert len(recs) == 20
    assert all(len(r[1]) >= 14 for r in recs)
    # timestamps are increasing
    ts = [r[0] for r in recs]
    assert ts == sorted(ts)


def test_c2_beacon_detected(c2_pcap):
    sigs = extract(c2_pcap)
    assert len(sigs) == 1
    s = sigs[0]
    # beaconing: regular 45s interval -> high beacon_score
    assert s["beacon_score"] >= 0.4
    assert s["suspicious_port"]  # 4444 in SUSPICIOUS_PORTS
    assert s["rare_dst_port"]
    # entropy: our 9-byte payload is not random, so not "high" by our threshold,
    # but beacon + suspicious port is the detection.
    assert s["mean_iat_s"] == pytest.approx(45.0, abs=0.01)


def test_exfil_high_entropy(exfil_pcap):
    sigs = extract(exfil_pcap)
    assert len(sigs) == 1
    s = sigs[0]
    assert s["high_entropy"]  # os.urandom payloads
    assert s["mean_entropy"] > 7.0


def test_benign_not_flagged(benign_pcap):
    sigs = extract(benign_pcap)
    assert len(sigs) == 1
    s = sigs[0]
    # port 443 is standard -> not rare/suspicious
    assert not s["rare_dst_port"]
    assert not s["suspicious_port"]
    # not periodic at C2 cadence (10s, low score)
    assert s["beacon_score"] < 0.4
    assert not s["high_entropy"]  # plain text GET


def test_flow_fields(c2_pcap):
    sigs = extract(c2_pcap)
    f = sigs[0]["flow"]
    assert f["src"] == "10.0.0.9"
    assert f["dst"] == "185.220.101.43"
    assert f["dst_port"] == 4444
    assert f["packets"] == 20
    assert f["proto"] == "tcp"


def test_multiple_flows(tmp_path):
    """Two distinct flows in one capture -> two signal dicts."""
    recs = pcap_writer.make_c2_beacon() + pcap_writer.make_benign_web()
    p = pcap_writer.write_classic_pcap(tmp_path / "two.pcap", recs)
    sigs = extract(p)
    assert len(sigs) == 2


def test_empty_pcap(tmp_path):
    p = pcap_writer.write_classic_pcap(tmp_path / "empty.pcap", [])
    sigs = extract(p)
    assert sigs == []


def test_entropy_values():
    """Shannon entropy: random ~8, constant ~0, text between."""
    import pkt, random
    random.seed(0)
    assert pkt.shannon_entropy(b"\x00" * 32) == pytest.approx(0.0, abs=0.01)
    # large uniform sample -> close to 8.0
    assert pkt.shannon_entropy(random.randbytes(2048)) > 7.0
    assert pkt.shannon_entropy(b"aaaa") == pytest.approx(0.0, abs=0.01)
    # text: moderate
    t = (b"the quick brown fox jumps over the lazy dog ") * 16
    assert 3.0 < pkt.shannon_entropy(t) < 6.0

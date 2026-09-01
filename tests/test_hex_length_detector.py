from hashid.detectors.hex_length import HexLengthDetector
from hashid.engine import identify


def test_32_char_hex_returns_three_ambiguous_candidates():
    candidates = HexLengthDetector().match("5d41402abc4b2a76b9719d911017c592")
    algorithms = {c.algorithm for c in candidates}
    assert algorithms == {"MD5", "NTLM", "MD4"}


def test_40_char_hex_returns_sha1_high_confidence():
    candidates = HexLengthDetector().match("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
    assert len(candidates) == 1
    assert candidates[0].algorithm == "SHA-1"
    assert candidates[0].confidence == "high"


def test_non_hex_text_returns_no_candidates():
    assert HexLengthDetector().match("no soy un hash") == []


def test_engine_identify_ranks_high_confidence_first():
    candidates = identify("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
    assert candidates[0].confidence == "high"
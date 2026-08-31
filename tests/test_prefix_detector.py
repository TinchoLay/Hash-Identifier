from hashid.detectors.prefix import PrefixDetector
from hashid.engine import identify


def test_bcrypt_prefix_is_recognized_high_confidence():
    candidates = PrefixDetector().match("$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G")
    assert len(candidates) == 1
    assert candidates[0].algorithm == "bcrypt"
    assert candidates[0].confidence == "high"


def test_argon2id_prefix_is_recognized():
    candidates = PrefixDetector().match("$argon2id$v=19$m=65536,t=3,p=4$somesalt$somehash")
    assert candidates[0].algorithm == "Argon2id"


def test_unknown_text_returns_no_candidates():
    assert PrefixDetector().match("hola mundo") == []


def test_engine_identify_finds_bcrypt():
    candidates = identify("$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G")
    assert candidates[0].algorithm == "bcrypt"


def test_engine_identify_returns_empty_for_empty_string():
    assert identify("") == []


def test_engine_identify_strips_whitespace():
    candidates = identify("  $2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G  ")
    assert candidates[0].algorithm == "bcrypt"
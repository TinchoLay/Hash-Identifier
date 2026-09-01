from hashid.detectors.shapes import DESCryptDetector, MySQL5Detector, NetNTLMDetector
from hashid.engine import identify


def test_netntlm_format_is_recognized():
    text = "b4b9b02e6f09a9bd760f388b67351e2b:11223344556677881122334455667788"
    candidates = NetNTLMDetector().match(text)
    assert candidates[0].algorithm == "NetNTLMv2"


def test_mysql5_format_is_recognized():
    candidates = MySQL5Detector().match("*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29")
    assert candidates[0].algorithm == "MySQL 4.1+ (MySQL5)"


def test_des_crypt_format_is_recognized():
    candidates = DESCryptDetector().match("eNBiY7dfnE4gY")
    assert candidates[0].algorithm == "DES crypt (Unix clásico)"


def test_engine_prefers_netntlm_shape_over_hex_length_guess():
    text = "b4b9b02e6f09a9bd760f388b67351e2b:11223344556677881122334455667788"
    candidates = identify(text)
    assert candidates[0].algorithm == "NetNTLMv2"
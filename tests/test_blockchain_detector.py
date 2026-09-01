from hashid.detectors.blockchain import BlockchainDetector
from hashid.engine import identify


def test_ethereum_address_is_recognized():
    candidates = BlockchainDetector().match("0x" + "a" * 40)
    assert candidates[0].algorithm == "Ethereum Address"


def test_ethereum_tx_hash_is_recognized():
    candidates = BlockchainDetector().match("0x" + "b" * 64)
    assert candidates[0].algorithm == "Ethereum Transaction/Block Hash (Keccak-256)"


def test_bitcoin_legacy_address_is_recognized():
    candidates = BlockchainDetector().match("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    assert candidates[0].algorithm == "Bitcoin Address (Legacy/P2SH, Base58Check)"


def test_bitcoin_bech32_address_is_recognized():
    candidates = BlockchainDetector().match("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
    assert candidates[0].algorithm == "Bitcoin Address (Bech32/SegWit nativo)"


def test_plain_hex_without_0x_is_not_matched_by_blockchain_detector():
    # Sin el prefijo "0x" no es blockchain para este detector — ese
    # caso lo cubre HexLengthDetector con confianza "low".
    assert BlockchainDetector().match("a" * 64) == []


def test_engine_includes_low_confidence_blockchain_guess_for_plain_64_hex():
    candidates = identify("a" * 64)
    algorithms = {c.algorithm for c in candidates}
    assert "Bitcoin Transaction Hash (doble SHA-256)" in algorithms
    assert "SHA-256" in algorithms
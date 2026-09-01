from hashid.detectors.cisco import CiscoType7Detector


def test_cisco_type7_example_is_recognized():
    # "094F471A1A0A" es el ejemplo clásico de Cisco Type 7 (decodifica a "cisco").
    candidates = CiscoType7Detector().match("094F471A1A0A")
    assert candidates[0].algorithm == "Cisco IOS Type 7 (XOR reversible, no es hash real)"
    assert candidates[0].confidence == "low"


def test_text_starting_with_letter_is_not_matched():
    # La sal de Cisco es siempre decimal (00-99) — si arranca con una
    # letra hex (a-f), no puede ser Type 7.
    assert CiscoType7Detector().match("aF471A1A0A") == []


def test_too_short_text_is_not_matched():
    assert CiscoType7Detector().match("09") == []
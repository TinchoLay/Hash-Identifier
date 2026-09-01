from hashid.detectors.jwt import JWTDetector

# Token de ejemplo estándar, el mismo que usa la documentación oficial de jwt.io
_SAMPLE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_valid_jwt_is_recognized_with_high_confidence():
    candidates = JWTDetector().match(_SAMPLE_JWT)
    assert candidates[0].algorithm == "JWT (JSON Web Token)"
    assert candidates[0].confidence == "high"
    assert "HS256" in candidates[0].reason


def test_three_segments_with_invalid_header_gets_medium_confidence():
    fake = "notbase64butvalidcharset.abcdef.ghijkl"
    candidates = JWTDetector().match(fake)
    assert candidates[0].confidence == "medium"


def test_two_segments_is_not_matched():
    assert JWTDetector().match("only.two") == []
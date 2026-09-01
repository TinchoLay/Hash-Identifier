"""Motor de orquestación: corre todos los detectores registrados sobre
un texto de entrada y devuelve los candidatos encontrados.

Corre TODOS los detectores siempre y junta la unión de resultados,
deduplicados por algoritmo y ordenados de mayor a menor confianza. Esto
es más correcto para un caso real: un analista de SOC prefiere ver
"podría ser MD5, NTLM o MD4" en vez de que la herramienta le oculte
candidatos igual de válidos.
"""

from hashid.detectors.base import Detector
from hashid.detectors.blockchain import BlockchainDetector
from hashid.detectors.cisco import CiscoType7Detector
from hashid.detectors.hex_length import HexLengthDetector
from hashid.detectors.jwt import JWTDetector
from hashid.detectors.prefix import PrefixDetector
from hashid.detectors.shapes import DESCryptDetector, MySQL5Detector, NetNTLMDetector
from hashid.models import Confidence, HashCandidate

_CONFIDENCE_RANK: dict[Confidence, int] = {"high": 0, "medium": 1, "low": 2}

_DETECTORS: list[Detector] = [
    # Señal fuerte: prefijo, shape o estructura verificada.
    PrefixDetector(),
    BlockchainDetector(),
    JWTDetector(),
    NetNTLMDetector(),
    MySQL5Detector(),
    # Señal media/débil: shape genérico o solo longitud.
    DESCryptDetector(),
    CiscoType7Detector(),
    HexLengthDetector(),
]


def identify(text: str) -> list[HashCandidate]:
    """Analiza `text` con todos los detectores registrados.

    Devuelve la unión de todos los candidatos encontrados, sin
    duplicados por algoritmo, ordenados de mayor a menor confianza.
    """
    text = text.strip()
    if not text:
        return []

    all_candidates: list[HashCandidate] = []
    for detector in _DETECTORS:
        all_candidates.extend(detector.match(text))

    best_by_algorithm: dict[str, HashCandidate] = {}
    for candidate in all_candidates:
        existing = best_by_algorithm.get(candidate.algorithm)
        if existing is None or (
            _CONFIDENCE_RANK[candidate.confidence] < _CONFIDENCE_RANK[existing.confidence]
        ):
            best_by_algorithm[candidate.algorithm] = candidate

    result = list(best_by_algorithm.values())
    result.sort(key=lambda c: _CONFIDENCE_RANK[c.confidence])
    return result
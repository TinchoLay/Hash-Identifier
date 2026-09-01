"""Motor de orquestación: corre todos los detectores registrados sobre
un texto de entrada y devuelve los candidatos encontrados.

A diferencia de la primera versión (que cortaba en el primer detector
que respondía), esta versión corre TODOS los detectores siempre y junta
la unión de resultados. Esto es más correcto para un caso real: un
analista de SOC prefiere ver "podría ser MD5, NTLM o MD4" en vez de que
la herramienta le oculte candidatos igual de válidos.
"""

from hashid.detectors.base import Detector
from hashid.detectors.hex_length import HexLengthDetector
from hashid.detectors.prefix import PrefixDetector
from hashid.detectors.shapes import DESCryptDetector, MySQL5Detector, NetNTLMDetector
from hashid.models import Confidence, HashCandidate

# Orden de "fuerza" de cada nivel de confianza, usado para ordenar el
# resultado final (más confiable primero) y para decidir con cuál
# quedarnos si dos detectores devuelven el mismo algoritmo.
_CONFIDENCE_RANK: dict[Confidence, int] = {"high": 0, "medium": 1, "low": 2}

# Lista de detectores activos. El orden acá no afecta el resultado
# (se corren todos igual) — pero mantenerlos agrupados por "fuerza de
# señal" ayuda a la lectura del archivo.
_DETECTORS: list[Detector] = [
    PrefixDetector(),
    NetNTLMDetector(),
    MySQL5Detector(),
    DESCryptDetector(),
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

    # Deduplicar por algoritmo: si dos detectores coincidieran en el
    # mismo algoritmo, nos quedamos con el de mayor confianza.
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
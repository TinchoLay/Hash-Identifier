"""Motor de orquestación: corre todos los detectores registrados sobre
un texto de entrada y devuelve los candidatos encontrados.

Esto es la "función pura" del proyecto — el equivalente a identify()
en el original, pero acá no tiene ningún if/elif de formato: solo
sabe recorrer una lista de Detector y juntar resultados. Es intencional
que este archivo se quede chico para siempre, incluso cuando agreguemos
20 detectores más.
"""

from hashid.detectors.base import Detector
from hashid.detectors.prefix import PrefixDetector
from hashid.models import HashCandidate

# Lista de detectores activos, en el orden en que se van a registrar.
# El motor los reordena por prioridad antes de correrlos, así que el
# orden acá no importa para el resultado — pero mantenerlo prolijo
# (agrupado por categoría) ayuda a la lectura.
_DETECTORS: list[Detector] = [
    PrefixDetector(),
]


def identify(text: str) -> list[HashCandidate]:
    """Analiza `text` con todos los detectores registrados.

    Devuelve la lista de candidatos del PRIMER detector (por prioridad)
    que encuentre algo. Si un detector de alta prioridad ya dio una
    respuesta con confianza "high", no tiene sentido seguir preguntando
    a detectores más débiles — por eso cortamos apenas hay un match.
    """
    text = text.strip()
    if not text:
        return []

    detectors_by_priority = sorted(_DETECTORS, key=lambda d: d.priority)

    for detector in detectors_by_priority:
        candidates = detector.match(text)
        if candidates:
            return candidates

    return []
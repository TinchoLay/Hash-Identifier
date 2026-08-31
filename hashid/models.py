"""Modelos de datos compartidos por todo el paquete hashid."""

from dataclasses import dataclass
from typing import Literal

Confidence = Literal["high", "medium", "low"]


@dataclass(frozen=True, slots=True)
class HashCandidate:
    """Un posible algoritmo que coincide con el texto analizado.

    Un solo hash de entrada puede producir varios candidatos (por ejemplo,
    un string de 32 caracteres hex podría ser MD5, NTLM o MD4 — todos
    tienen la misma longitud, así que no podemos estar 100% seguros).
    """

    algorithm: str
    confidence: Confidence
    reason: str
    detector_name: str
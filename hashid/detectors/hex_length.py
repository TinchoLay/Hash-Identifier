"""Detector de hashes "crudos": strings hexadecimales sin ningún
prefijo que los identifique.

A diferencia de PrefixDetector (que resuelve casos sin ambigüedad),
este detector trabaja con la única pista disponible cuando un hash
no se auto-identifica: su LONGITUD. El problema es que la longitud
sola casi nunca alcanza para estar seguro — varios algoritmos
distintos producen salidas del mismo tamaño. Por eso, a diferencia
de PrefixDetector, acá SIEMPRE se devuelven TODOS los algoritmos
posibles para ese largo, con confianza media o baja según qué tan
"disputada" esté esa longitud.
"""

import re

from hashid.detectors.base import Detector
from hashid.models import Confidence, HashCandidate

# Un string hex válido: solo dígitos 0-9 y letras a-f (mayúscula o minúscula).
_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")

# Cada fila: (longitud en caracteres, algoritmo, confianza, nota)
# Longitudes muy "disputadas" (varios algoritmos comparten el mismo largo,
# como 32) llevan confianza "medium". Longitudes casi exclusivas de un
# solo algoritmo llevan "high" — aunque no tengan prefijo, son bastante
# confiables igual.
HEX_LENGTH_RULES: list[tuple[int, str, Confidence, str]] = [
    (8, "CRC32", "medium", "8 caracteres hex — típico de un checksum CRC32"),
    (16, "MySQL323 (legacy)", "low", "16 caracteres hex — formato antiguo de MySQL, poco usado hoy"),
    (32, "MD5", "medium", "32 caracteres hex — comparte largo con NTLM y MD4"),
    (32, "NTLM", "medium", "32 caracteres hex — comparte largo con MD5 y MD4"),
    (32, "MD4", "low", "32 caracteres hex — mismo largo que MD5/NTLM, poco frecuente hoy"),
    (40, "SHA-1", "high", "40 caracteres hex — prácticamente exclusivo de SHA-1"),
    (56, "SHA-224", "high", "56 caracteres hex — prácticamente exclusivo de SHA-224"),
    (64, "SHA-256", "high", "64 caracteres hex — también usado por SHA3-256"),
    (96, "SHA-384", "high", "96 caracteres hex — prácticamente exclusivo de SHA-384"),
    (128, "SHA-512", "high", "128 caracteres hex — también usado por SHA3-512 y Whirlpool"),
]


class HexLengthDetector(Detector):
    """Reconoce hashes crudos en hex a partir de su longitud."""

    name = "HexLengthDetector"
    # Prioridad alta (número grande = se prueba tarde): es la señal más
    # débil que tenemos, así que solo se usa si nadie más respondió antes.
    priority = 50

    def match(self, text: str) -> list[HashCandidate]:
        if not _HEX_PATTERN.match(text):
            return []

        length = len(text)
        matches = [
            HashCandidate(
                algorithm=algorithm,
                confidence=confidence,
                reason=f"{length} caracteres hexadecimales — {note}",
                detector_name=self.name,
            )
            for rule_length, algorithm, confidence, note in HEX_LENGTH_RULES
            if rule_length == length
        ]
        return matches
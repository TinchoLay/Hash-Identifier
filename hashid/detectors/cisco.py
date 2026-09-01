"""Detector de contraseñas ofuscadas al estilo Cisco IOS.

Cisco IOS tiene dos esquemas de "type" para contraseñas:

- Type 5: es matemáticamente el MISMO formato que un MD5 crypt estándar
  de Unix ($1$salt$hash). Por eso NO tiene una clase propia acá — ya lo
  cubre PrefixDetector (fila "$1$" en prefix.py). No hay forma de
  distinguir un $1$ de Cisco de un $1$ de Linux mirando solo el string:
  son el mismo algoritmo, byte por byte.
- Type 7: es un cifrado XOR reversible (NO es un hash criptográfico
  real — es "ofuscación", trivial de revertir sin fuerza bruta). Tiene
  una forma reconocible: dos dígitos decimales (la "sal", 00-99)
  seguidos de pares de caracteres hexadecimales.
"""

import re

from hashid.detectors.base import Detector
from hashid.models import HashCandidate

# Dos dígitos DECIMALES (no hex — la sal de Cisco va de 00 a 99, nunca
# usa a-f) seguidos de al menos un byte más (2 hex) en pares.
_CISCO_TYPE7_PATTERN = re.compile(r"^[0-9]{2}([0-9a-fA-F]{2})+$")


class CiscoType7Detector(Detector):
    """Reconoce contraseñas Cisco IOS "type 7" (XOR reversible, no es hash real)."""

    name = "CiscoType7Detector"
    # Prioridad baja (número alto): el patrón es genérico — cualquier
    # hex de longitud par que empiece con dos dígitos decimales
    # matchea — así que se solapa mucho con hashes hex normales.
    priority = 45

    def match(self, text: str) -> list[HashCandidate]:
        if len(text) >= 4 and _CISCO_TYPE7_PATTERN.match(text):
            return [
                HashCandidate(
                    algorithm="Cisco IOS Type 7 (XOR reversible, no es hash real)",
                    confidence="low",
                    reason=(
                        "dos dígitos decimales (sal) + pares hexadecimales — "
                        "patrón genérico, se solapa fácil con hashes hex normales"
                    ),
                    detector_name=self.name,
                )
            ]
        return []
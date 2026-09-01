"""Detector de JSON Web Tokens (JWT).

A diferencia de todos los detectores anteriores, este no se conforma
con mirar la "forma" del texto (tres segmentos separados por puntos)
— eso solo demuestra que el shape es compatible. Para confirmar de
verdad que es un JWT, decodifica el primer segmento (el header) en
Base64URL y confirma que el resultado es JSON válido con un campo
"alg" (el algoritmo de firma, ej. "HS256", "RS256").

Esta es la única verificación "activa" del proyecto: los demás
detectores solo comparan texto contra un patrón, este además
ejecuta una decodificación real.
"""

import base64
import json
import re

from hashid.detectors.base import Detector
from hashid.models import HashCandidate

# JWT = tres segmentos en Base64URL (alfabeto A-Z a-z 0-9 - _, sin
# padding "=") separados por puntos: header.payload.signature
_JWT_SHAPE_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def _try_decode_header(header_segment: str) -> dict | None:
    """Intenta decodificar el header de un JWT como JSON.

    Base64URL no lleva padding, pero el decodificador de Python sí lo
    exige — por eso se completa con "=" hasta el múltiplo de 4 antes
    de decodificar.
    """
    padded = header_segment + "=" * (-len(header_segment) % 4)
    try:
        decoded_bytes = base64.urlsafe_b64decode(padded)
        return json.loads(decoded_bytes)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


class JWTDetector(Detector):
    """Reconoce JSON Web Tokens, verificando el header decodificado."""

    name = "JWTDetector"
    priority = 15  # shape muy distintivo (tres segmentos con puntos)

    def match(self, text: str) -> list[HashCandidate]:
        if not _JWT_SHAPE_PATTERN.match(text):
            return []

        header_segment = text.split(".", 1)[0]
        header_json = _try_decode_header(header_segment)

        if header_json is not None and "alg" in header_json:
            algorithm_used = header_json.get("alg", "desconocido")
            return [
                HashCandidate(
                    algorithm="JWT (JSON Web Token)",
                    confidence="high",
                    reason=(
                        f"header decodificado como JSON válido con alg='{algorithm_used}' "
                        "— estructura confirmada, no solo shape"
                    ),
                    detector_name=self.name,
                )
            ]

        # El shape encaja (tres segmentos base64url) pero el header no
        # decodificó a JSON con "alg" — probablemente no es un JWT real,
        # solo coincidencia de formato.
        return [
            HashCandidate(
                algorithm="JWT (JSON Web Token) — posible",
                confidence="medium",
                reason=(
                    "tres segmentos base64url separados por '.', pero el header "
                    "no pudo decodificarse como JSON con un campo 'alg'"
                ),
                detector_name=self.name,
            )
        ]
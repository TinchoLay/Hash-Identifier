"""Detectores de formatos con una "forma" estructural particular:
no alcanza con mirar un prefijo fijo ni solo la longitud, hay que
reconocer un patrón (separadores, alfabeto restringido, secciones).

Cada formato de este archivo es lo bastante distinto de los otros como
para merecer su propia clase, en vez de una tabla de datos compartida
como en prefix.py — acá la lógica de match() cambia de verdad de un
formato a otro.
"""

import re

from hashid.detectors.base import Detector
from hashid.models import HashCandidate

# NetNTLMv2: dos mitades hex de 32 caracteres separadas por ":".
# Formato típico: HASH:CHALLENGE (ambas partes de 32 hex).
_NETNTLM_PATTERN = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")

# MySQL 4.1+ ("MySQL5"): siempre empieza con "*" seguido de 40 hex
# (un SHA-1 en mayúsculas, con el asterisco como marca de formato).
_MYSQL5_PATTERN = re.compile(r"^\*[0-9A-Fa-f]{40}$")

# DES crypt clásico de Unix: 13 caracteres del alfabeto base64 "crypt"
# (no es base64 estándar: usa ./0-9A-Za-z, sin +, / ni =).
_DES_CRYPT_PATTERN = re.compile(r"^[./0-9A-Za-z]{13}$")


class NetNTLMDetector(Detector):
    """Reconoce hashes NetNTLMv2 (formato HASH:CHALLENGE)."""

    name = "NetNTLMDetector"
    priority = 20  # forma muy específica, casi tan confiable como un prefijo

    def match(self, text: str) -> list[HashCandidate]:
        if _NETNTLM_PATTERN.match(text):
            return [
                HashCandidate(
                    algorithm="NetNTLMv2",
                    confidence="high",
                    reason="dos bloques hex de 32 caracteres separados por ':' (hash:challenge)",
                    detector_name=self.name,
                )
            ]
        return []


class MySQL5Detector(Detector):
    """Reconoce hashes MySQL 4.1+ (formato *SHA1EN MAYÚSCULAS)."""

    name = "MySQL5Detector"
    priority = 20

    def match(self, text: str) -> list[HashCandidate]:
        if _MYSQL5_PATTERN.match(text):
            return [
                HashCandidate(
                    algorithm="MySQL 4.1+ (MySQL5)",
                    confidence="high",
                    reason="asterisco inicial + 40 caracteres hex — formato mysql.user.Password",
                    detector_name=self.name,
                )
            ]
        return []


class DESCryptDetector(Detector):
    """Reconoce hashes DES crypt clásico de Unix (13 caracteres)."""

    name = "DESCryptDetector"
    # Prioridad más baja que las otras formas: el alfabeto de 13
    # caracteres es más fácil de confundir con texto arbitrario corto,
    # así que preferimos que los detectores más específicos respondan
    # primero si hubiera solapamiento.
    priority = 40

    def match(self, text: str) -> list[HashCandidate]:
        if _DES_CRYPT_PATTERN.match(text):
            return [
                HashCandidate(
                    algorithm="DES crypt (Unix clásico)",
                    confidence="medium",
                    reason="13 caracteres del alfabeto crypt clásico — formato /etc/passwd antiguo",
                    detector_name=self.name,
                )
            ]
        return []
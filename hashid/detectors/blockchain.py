"""Detector de formatos relacionados con blockchain: direcciones y
hashes de transacción/bloque de Ethereum y Bitcoin.

A diferencia de los hashes "planos" (que son solo hex), estos formatos
tienen marcas estructurales reconocibles: Ethereum antepone "0x" a todo,
y las direcciones de Bitcoin usan alfabetos (Base58Check o Bech32) que
excluyen caracteres ambiguos (0, O, I, l) para evitar errores al
transcribirlas a mano.
"""

import re

from hashid.detectors.base import Detector
from hashid.models import HashCandidate

# Ethereum: todo arranca con "0x". Una dirección son 20 bytes (40 hex);
# un hash de transacción o de bloque son 32 bytes (64 hex, Keccak-256).
_ETH_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ETH_HASH_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")

# Bitcoin legacy / P2SH: Base58Check, arranca con "1" o "3", 26-34
# caracteres. El alfabeto Base58 excluye 0, O, I, l a propósito.
_BTC_LEGACY_ADDRESS_PATTERN = re.compile(r"^[13][A-HJ-NP-Za-km-z1-9]{25,34}$")

# Bitcoin SegWit nativo (Bech32): arranca con "bc1".
_BTC_BECH32_ADDRESS_PATTERN = re.compile(r"^bc1[a-z0-9]{6,90}$")

# Cada fila: (patrón compilado, algoritmo, confianza, motivo)
_BLOCKCHAIN_RULES: list[tuple[re.Pattern, str, str, str]] = [
    (_ETH_HASH_PATTERN, "Ethereum Transaction/Block Hash (Keccak-256)", "high",
     "prefijo '0x' + 64 caracteres hex — hash de 32 bytes típico de Ethereum"),
    (_ETH_ADDRESS_PATTERN, "Ethereum Address", "high",
     "prefijo '0x' + 40 caracteres hex — dirección de cuenta de 20 bytes"),
    (_BTC_LEGACY_ADDRESS_PATTERN, "Bitcoin Address (Legacy/P2SH, Base58Check)", "high",
     "Base58Check empezando en '1' o '3' — dirección clásica o multisig de Bitcoin"),
    (_BTC_BECH32_ADDRESS_PATTERN, "Bitcoin Address (Bech32/SegWit nativo)", "high",
     "prefijo 'bc1' — dirección SegWit nativa de Bitcoin"),
]


class BlockchainDetector(Detector):
    """Reconoce direcciones y hashes de Ethereum y Bitcoin."""

    name = "BlockchainDetector"
    # Prioridad alta (se prueba temprano): estos shapes son muy
    # distintivos (prefijos "0x"/"bc1", alfabetos restringidos), casi
    # tan confiables como un prefijo PHC.
    priority = 15

    def match(self, text: str) -> list[HashCandidate]:
        for pattern, algorithm, confidence, note in _BLOCKCHAIN_RULES:
            if pattern.match(text):
                return [
                    HashCandidate(
                        algorithm=algorithm,
                        confidence=confidence,
                        reason=note,
                        detector_name=self.name,
                    )
                ]
        return []
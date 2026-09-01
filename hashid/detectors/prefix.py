"""Detector de hashes que se identifican por un prefijo fijo.

Muchos formatos modernos de hash (los que siguen el estándar PHC —
"Password Hashing Competition") incluyen el nombre del algoritmo dentro
del propio string. Por ejemplo, un hash bcrypt siempre arranca con
`$2b$`, y un hash Argon2id siempre arranca con `$argon2id$`.

Esto es la señal MÁS fuerte que existe para identificar un hash: no hay
ambigüedad posible, el hash literalmente te dice qué es.
"""

from hashid.detectors.base import Detector
from hashid.models import HashCandidate

# Cada fila es: (prefijo, nombre del algoritmo, explicación corta)
# Data-driven: para agregar un formato nuevo con prefijo fijo, se agrega
# una fila acá — no se toca la lógica de match().
PREFIX_RULES: list[tuple[str, str, str]] = [
    ("$argon2id$", "Argon2id", "PHC string moderno, variante id (recomendada por OWASP)"),
    ("$argon2i$", "Argon2i", "PHC string moderno, variante i (resistente a side-channel)"),
    ("$argon2d$", "Argon2d", "PHC string moderno, variante d (resistente a GPU)"),
    ("$2b$", "bcrypt", "PHC string bcrypt, variante 2b (actual)"),
    ("$2a$", "bcrypt", "PHC string bcrypt, variante 2a (legacy)"),
    ("$2y$", "bcrypt", "PHC string bcrypt, variante 2y (compatibilidad PHP)"),
    ("$6$", "SHA-512 crypt", "Unix crypt(3) con SHA-512, usado en /etc/shadow"),
    ("$5$", "SHA-256 crypt", "Unix crypt(3) con SHA-256, usado en /etc/shadow"),
    ("$1$", "MD5 crypt", "Unix crypt(3) con MD5, legacy — formato idéntico al usado por Cisco IOS 'type 5'"),
    ("$apr1$", "APR1 (Apache MD5)", "variante de MD5 crypt usada por Apache htpasswd"),
    ("pbkdf2_sha256$", "PBKDF2-SHA256 (Django)", "formato de hash de contraseñas de Django"),
    ("pbkdf2:sha256:", "PBKDF2-SHA256 (Werkzeug/Flask)", "formato usado por Werkzeug/Flask"),
]


class PrefixDetector(Detector):
    """Reconoce hashes que se auto-identifican mediante un prefijo fijo."""

    name = "PrefixDetector"
    # Prioridad más baja = se prueba primero. Los prefijos son la señal
    # más fuerte que existe, así que van antes que cualquier otra cosa.
    priority = 10

    def match(self, text: str) -> list[HashCandidate]:
        for prefix, algorithm, note in PREFIX_RULES:
            if text.startswith(prefix):
                return [
                    HashCandidate(
                        algorithm=algorithm,
                        confidence="high",
                        reason=f"prefijo `{prefix}` — {note}",
                        detector_name=self.name,
                    )
                ]
        return []
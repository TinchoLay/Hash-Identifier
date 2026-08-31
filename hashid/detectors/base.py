"""Clase base para todos los detectores de hash.

Cada formato de hash que la herramienta reconoce es una subclase de
Detector. Esto reemplaza la cascada de if/elif del proyecto original:
en vez de una función gigante que pregunta "¿es esto? ¿es lo otro?",
tenemos una lista de objetos, cada uno experto en una sola cosa.
"""

from abc import ABC, abstractmethod

from hashid.models import HashCandidate


class Detector(ABC):
    """Interfaz que debe cumplir todo detector de formato de hash."""

    #: Nombre legible del detector, usado en logs y en modo batch.
    name: str = "UnnamedDetector"

    #: Prioridad de ejecución: los detectores con número más BAJO
    #: se prueban primero. Esto reemplaza el orden implícito de los
    #: "6 pasos" del original — acá el orden es explícito y configurable.
    priority: int = 100

    @abstractmethod
    def match(self, text: str) -> list[HashCandidate]:
        """Analiza `text` y devuelve una lista de candidatos (puede estar vacía).

        Contrato importante: este método NO debe lanzar excepciones por
        entradas raras (texto vacío, caracteres extraños, etc.) — debe
        devolver una lista vacía. Los detectores deben ser funciones puras:
        mismo texto de entrada, mismo resultado siempre, sin tocar archivos
        ni red ni estado global.
        """
        raise NotImplementedError
"""Interfaz de línea de comandos del proyecto hashid.

Construida con Click en vez de argparse porque anticipamos varios
subcomandos (identify, batch, interactive) que van a compartir lógica
de formateo de salida — Click maneja grupos de subcomandos de forma
más limpia que argparse con subparsers manuales.
"""

import csv
import io
import json
import sys

import click
from rich.console import Console
from rich.table import Table

from hashid.engine import identify as identify_hash
from hashid.models import HashCandidate

console = Console()

_CONFIDENCE_LABELS = {
    "high": "[green]alta[/green]",
    "medium": "[yellow]media[/yellow]",
    "low": "[red]baja[/red]",
}


@click.group()
@click.version_option(package_name="hashid")
def main() -> None:
    """hashid — identificador de hashes con arquitectura basada en detectores."""


def _print_table(candidates: list[HashCandidate], subject: str) -> None:
    if not candidates:
        console.print(f"[yellow]No se encontraron coincidencias para:[/yellow] {subject}")
        return

    table = Table(title=f"Resultados para: {subject}")
    table.add_column("Algoritmo", style="bold cyan")
    table.add_column("Confianza")
    table.add_column("Motivo", overflow="fold")
    table.add_column("Detector", style="dim")

    for candidate in candidates:
        table.add_row(
            candidate.algorithm,
            _CONFIDENCE_LABELS.get(candidate.confidence, candidate.confidence),
            candidate.reason,
            candidate.detector_name,
        )

    console.print(table)


def _to_json(candidates: list[HashCandidate]) -> str:
    return json.dumps(
        [
            {
                "algorithm": c.algorithm,
                "confidence": c.confidence,
                "reason": c.reason,
                "detector_name": c.detector_name,
            }
            for c in candidates
        ],
        indent=2,
        ensure_ascii=False,
    )


def _to_csv(candidates: list[HashCandidate]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["algorithm", "confidence", "reason", "detector_name"])
    for c in candidates:
        writer.writerow([c.algorithm, c.confidence, c.reason, c.detector_name])
    return buffer.getvalue()


@main.command()
@click.argument("hash_text")
@click.option(
    "--format", "output_format",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    help="Formato de salida.",
)
def identify(hash_text: str, output_format: str) -> None:
    """Identifica un único hash y muestra los algoritmos candidatos."""
    candidates = identify_hash(hash_text)

    if output_format == "table":
        _print_table(candidates, subject=hash_text)
    elif output_format == "json":
        click.echo(_to_json(candidates))
    elif output_format == "csv":
        click.echo(_to_csv(candidates), nl=False)

    if not candidates:
        sys.exit(1)


if __name__ == "__main__":
    main()
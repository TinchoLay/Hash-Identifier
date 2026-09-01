"""Interfaz de línea de comandos del proyecto hashid.

Construida con Click porque compartimos lógica de formateo de salida
entre los tres subcomandos (identify, batch, interactive) — Click
maneja grupos de subcomandos de forma más limpia que argparse con
subparsers manuales.
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

_EXIT_KEYWORDS = {"salir", "exit", "quit"}


@click.group()
@click.version_option(package_name="hashid")
def main() -> None:
    """hashid — identificador de hashes con arquitectura basada en detectores."""


# ---------------------------------------------------------------------
# Helpers de formateo compartidos entre identify y batch
# ---------------------------------------------------------------------

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


# ---------------------------------------------------------------------
# identify — un solo hash
# ---------------------------------------------------------------------

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


# ---------------------------------------------------------------------
# batch — un archivo con muchos hashes
# ---------------------------------------------------------------------

def _render_batch_table(results: list[tuple[str, list[HashCandidate]]]) -> None:
    table = Table(title=f"Resultados de batch ({len(results)} hashes)")
    table.add_column("Hash (entrada)", style="bold cyan", overflow="fold")
    table.add_column("Algoritmo")
    table.add_column("Confianza")
    table.add_column("Detector", style="dim")

    no_match_count = 0
    for hash_text, candidates in results:
        shown = hash_text if len(hash_text) <= 40 else hash_text[:37] + "..."
        if not candidates:
            no_match_count += 1
            table.add_row(shown, "[red]sin coincidencias[/red]", "-", "-")
            continue
        for i, candidate in enumerate(candidates):
            table.add_row(
                shown if i == 0 else "",
                candidate.algorithm,
                _CONFIDENCE_LABELS.get(candidate.confidence, candidate.confidence),
                candidate.detector_name,
            )

    console.print(table)
    console.print(
        f"\n[bold]{len(results)}[/bold] hashes analizados, "
        f"[bold]{no_match_count}[/bold] sin coincidencias."
    )


def _batch_to_json(results: list[tuple[str, list[HashCandidate]]]) -> str:
    return json.dumps(
        [
            {
                "input": hash_text,
                "candidates": [
                    {
                        "algorithm": c.algorithm,
                        "confidence": c.confidence,
                        "reason": c.reason,
                        "detector_name": c.detector_name,
                    }
                    for c in candidates
                ],
            }
            for hash_text, candidates in results
        ],
        indent=2,
        ensure_ascii=False,
    )


def _batch_to_csv(results: list[tuple[str, list[HashCandidate]]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["input", "algorithm", "confidence", "reason", "detector_name"])
    for hash_text, candidates in results:
        if not candidates:
            writer.writerow([hash_text, "", "", "sin coincidencias", ""])
            continue
        for c in candidates:
            writer.writerow([hash_text, c.algorithm, c.confidence, c.reason, c.detector_name])
    return buffer.getvalue()


@main.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--format", "output_format",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    help="Formato de salida.",
)
@click.option(
    "--output", "output_file",
    type=click.Path(dir_okay=False),
    default=None,
    help="Guardar el resultado en un archivo (solo válido con --format json o csv).",
)
def batch(input_file: str, output_format: str, output_file: str | None) -> None:
    """Analiza todos los hashes de un archivo de texto, uno por línea.

    Las líneas vacías y las que empiezan con '#' se ignoran (permite
    usar comentarios dentro del archivo de hashes).
    """
    with open(input_file, encoding="utf-8") as f:
        raw_lines = f.readlines()

    hashes = [
        line.strip() for line in raw_lines
        if line.strip() and not line.strip().startswith("#")
    ]

    if not hashes:
        console.print("[yellow]El archivo no tiene hashes para analizar (¿vacío o solo comentarios?).[/yellow]")
        sys.exit(1)

    if output_format == "table" and output_file:
        console.print("[red]--output solo es válido junto con --format json o csv.[/red]")
        sys.exit(2)

    results = [(h, identify_hash(h)) for h in hashes]
    no_match_count = sum(1 for _, candidates in results if not candidates)

    if output_format == "table":
        _render_batch_table(results)
    else:
        text = _batch_to_json(results) if output_format == "json" else _batch_to_csv(results)
        if output_file:
            with open(output_file, "w", encoding="utf-8", newline="") as f:
                f.write(text)
            console.print(f"[green]Resultado guardado en:[/green] {output_file}")
        else:
            click.echo(text, nl=False)

    if no_match_count == len(results):
        sys.exit(1)


# ---------------------------------------------------------------------
# interactive — loop pidiendo hashes uno por uno
# ---------------------------------------------------------------------

@main.command()
def interactive() -> None:
    """Modo interactivo: pide hashes uno tras otro hasta que se escriba 'salir'."""
    console.print("[bold cyan]hashid — modo interactivo[/bold cyan]")
    console.print("Pegá un hash y presioná Enter. Escribí 'salir' o Ctrl+C para terminar.\n")

    while True:
        try:
            entered = click.prompt("hash", prompt_suffix="> ")
        except click.Abort:
            console.print("\n[dim]Saliendo...[/dim]")
            break

        stripped = entered.strip()
        if stripped.lower() in _EXIT_KEYWORDS:
            console.print("[dim]Saliendo...[/dim]")
            break
        if not stripped:
            continue

        candidates = identify_hash(stripped)
        _print_table(candidates, subject=stripped)
        console.print()


if __name__ == "__main__":
    main()
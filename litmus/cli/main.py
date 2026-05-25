"""
Litmus CLI — behavioral control validation for cloud environments.
"""

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box

from litmus.controls.nist_800_53.ac.ac_2 import AC2_SPEC
from litmus.controls.nist_800_53.ac.ac_3 import AC3_SPEC
from litmus.engine.runner import EngineConfig, LitmusEngine
from litmus.probes.aws.s3_probe import AWSIAMProbe, AWSS3Probe
from litmus.probes.base import ValidationStatus

console = Console()

CONTROL_REGISTRY = {
    "nist-800-53/ac-2": AC2_SPEC,
    "nist-800-53/ac-3": AC3_SPEC,
}

PROBE_REGISTRY = [
    AWSS3Probe(),
    AWSIAMProbe(),
]


@click.group()
@click.version_option()
def cli():
    """Litmus — behavioral control validation, mapped to OSCAL."""
    pass


@cli.command()
@click.option(
    "--controls", "-c",
    multiple=True,
    default=["nist-800-53/ac-3"],
    show_default=True,
    help="Control IDs to validate (e.g. nist-800-53/ac-3). Repeatable.",
)
@click.option("--system-name", default="unnamed-system", show_default=True)
@click.option("--system-id", default="system-001", show_default=True)
@click.option(
    "--output", "-o",
    type=click.Choice(["summary", "oscal", "both"]),
    default="both",
    show_default=True,
)
@click.option(
    "--output-file", "-f",
    type=click.Path(),
    default=None,
    help="Write OSCAL output to file (default: stdout)",
)
@click.option(
    "--var", "-v",
    multiple=True,
    help="Context variables for probe templates, e.g. -v target_bucket=my-bucket",
)
@click.option("--fail-fast", is_flag=True, default=False)
def run(controls, system_name, system_id, output, output_file, var, fail_fast):
    """Run behavioral control validation against your environment."""

    # Parse --var k=v pairs into context dict
    context = {}
    for v in var:
        if "=" not in v:
            console.print(f"[red]Invalid --var format '{v}' — expected key=value[/red]")
            sys.exit(1)
        k, val = v.split("=", 1)
        context[k.strip()] = val.strip()

    # Resolve control specs
    specs = []
    for control_id in controls:
        spec = CONTROL_REGISTRY.get(control_id)
        if spec is None:
            console.print(f"[red]Unknown control: {control_id}[/red]")
            console.print(f"Available: {', '.join(CONTROL_REGISTRY.keys())}")
            sys.exit(1)
        specs.append(spec)

    config = EngineConfig(
        system_name=system_name,
        system_id=system_id,
        context=context,
        fail_fast=fail_fast,
    )

    console.print(f"\n[bold cyan]Litmus[/bold cyan] — behavioral control validation")
    console.print(f"System: [bold]{system_name}[/bold]")
    console.print(f"Controls: {', '.join(controls)}\n")

    engine = LitmusEngine(probes=PROBE_REGISTRY)
    assessment = asyncio.run(engine.assess(specs=specs, config=config))

    if output in ("summary", "both"):
        _print_summary(assessment)

    if output in ("oscal", "both"):
        oscal_json = json.dumps(assessment.oscal_document, indent=2, default=str)
        if output_file:
            Path(output_file).write_text(oscal_json)
            console.print(f"\n[green]OSCAL output written to {output_file}[/green]")
        else:
            console.print("\n[bold]OSCAL Assessment Results:[/bold]")
            console.print(oscal_json)

    sys.exit(0 if assessment.success else 1)


@cli.command()
def list_controls():
    """List all available control specs."""
    table = Table(title="Available Controls", box=box.ROUNDED)
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Test Cases", justify="right")
    table.add_column("Framework")

    for control_id, spec in CONTROL_REGISTRY.items():
        table.add_row(
            control_id,
            spec.title,
            str(len(spec.test_cases)),
            spec.framework,
        )

    console.print(table)


def _print_summary(assessment):
    """Print a rich summary table of assessment results."""
    table = Table(title="Assessment Results", box=box.ROUNDED)
    table.add_column("Test Case", style="cyan")
    table.add_column("Control")
    table.add_column("Status")
    table.add_column("Summary")

    for result in assessment.results:
        status_str = {
            ValidationStatus.PASS: "[green]PASS[/green]",
            ValidationStatus.FAIL: "[red]FAIL[/red]",
            ValidationStatus.ERROR: "[yellow]ERROR[/yellow]",
        }[result.status]

        table.add_row(
            result.test_case_id,
            result.control_id,
            status_str,
            result.evidence_summary[:80] + "..." if len(result.evidence_summary) > 80 else result.evidence_summary,
        )

    console.print(table)
    console.print(
        f"\nTotal: {assessment.total} | "
        f"[green]Passed: {assessment.passed}[/green] | "
        f"[red]Failed: {assessment.failed}[/red] | "
        f"[yellow]Errors: {assessment.errors}[/yellow]"
    )

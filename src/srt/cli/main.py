"""`srt` CLI entrypoint.

Commands:
  srt info               Show platform + safety status.
  srt list               List registered modules.
  srt selftest           Probe SDR + DB + safety. Returns non-zero if any fails.
  srt run <module> ...   Run a single module.
  srt scenario <file>    Run a YAML scenario.
  srt report             Generate report from a past session.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click
import structlog
from rich.console import Console
from rich.table import Table

from srt import __version__
from srt.core import db, registry, safety, sdr
from srt.core.orchestrator import Orchestrator, Scenario
from srt.core.reporter import write_json, write_markdown, write_pdf

console = Console()


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(message)s")
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(level),
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
    )


@click.group(help=f"sniffer-rt v{__version__} - lab-only RF red-team platform")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _configure_logging(verbose)
    registry.autodiscover()


@cli.command(help="Show version, safety, SDR and DB status.")
def info() -> None:
    auth, whitelist = safety.evaluate()
    radios = sdr.probe()
    db_ok = db.ping()

    table = Table(title=f"sniffer-rt v{__version__}")
    table.add_column("Item")
    table.add_column("Status")
    table.add_row("Authorization", "OK" if auth.ok else f"NOT OK ({auth.reason})")
    table.add_row("Authorized bands", str(len(auth.authorized_bands_mhz)))
    table.add_row("Whitelist kinds", ", ".join(whitelist) or "—")
    table.add_row("Database", "reachable" if db_ok else "unreachable")
    table.add_row("SDR backends", ", ".join(r.backend for r in radios) or "none")
    table.add_row("Modules registered", str(len(registry.list_all())))
    console.print(table)


@cli.command("list", help="List registered modules.")
@click.option("--protocol", help="Filter by protocol")
@click.option("--risk", help="Filter by risk (passive|active-lab|destructive-lab)")
def list_cmd(protocol: str | None, risk: str | None) -> None:
    table = Table(title="Modules")
    table.add_column("Name", style="bold")
    table.add_column("Protocol")
    table.add_column("Risk")
    table.add_column("MITRE")
    table.add_column("Description")
    for cls in registry.list_all():
        if protocol and cls.protocol != protocol:
            continue
        if risk and cls.risk.value != risk:
            continue
        table.add_row(
            cls.name,
            cls.protocol,
            cls.risk.value,
            ",".join(cls.mitre_ttp) or "—",
            cls.description or "",
        )
    console.print(table)


@cli.command(help="Probe radios, DB and safety. Exit code 0 only if all OK.")
def selftest() -> None:
    auth, _ = safety.evaluate()
    radios = sdr.probe()
    db_ok = db.ping()
    failures: list[str] = []
    if not radios:
        failures.append("no SDR detected")
    if not db_ok:
        failures.append("database unreachable")
    if not auth.ok:
        failures.append(f"authorization not loaded ({auth.reason})")
    payload = {
        "auth_ok": auth.ok,
        "auth_reason": auth.reason,
        "db_ok": db_ok,
        "radios": [r.__dict__ for r in radios],
        "failures": failures,
    }
    console.print_json(json.dumps(payload, default=str))
    sys.exit(0 if not failures else 1)


@cli.command(help="Run a single module by name.")
@click.argument("module_name")
@click.option("--param", "-p", "params", multiple=True, help="key=value (repeatable)")
@click.option("--dry-run", is_flag=True, help="Skip module body but record a result")
@click.option("--operator", help="Override operator name")
def run(module_name: str, params: tuple[str, ...], dry_run: bool,
        operator: str | None) -> None:
    cls = registry.get(module_name)
    parsed: dict[str, str] = {}
    for raw in params:
        if "=" not in raw:
            raise click.BadParameter(f"expected key=value, got {raw!r}")
        k, v = raw.split("=", 1)
        parsed[k.strip()] = v
    orch = Orchestrator(dry_run=dry_run, operator=operator)
    result = orch.run_module(cls(), params=parsed)
    console.print_json(json.dumps(result.__dict__, default=str))
    sys.exit(0 if result.status.value == "ok" else 1)


@cli.command(help="Run a YAML scenario from `scenarios/`.")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--dry-run", is_flag=True)
@click.option("--operator", help="Override operator name")
@click.option(
    "--var", "vars_list", multiple=True,
    help="Variable override in key=value format (repeatable)",
)
def scenario(path: Path, dry_run: bool, operator: str | None,
             vars_list: tuple[str, ...]) -> None:
    sc = Scenario.load(path)
    # Parse --var options into dict
    cli_vars: dict[str, str] = {}
    for raw in vars_list:
        if "=" not in raw:
            raise click.BadParameter(f"expected key=value, got {raw!r}")
        k, v = raw.split("=", 1)
        cli_vars[k.strip()] = v

    orch = Orchestrator(dry_run=dry_run, operator=operator)
    results = orch.run_scenario(sc, cli_vars=cli_vars)
    out_json = write_json(results, sc.name)
    out_md = write_markdown(results, sc.name)
    console.print(f"[green]wrote[/] {out_json}")
    console.print(f"[green]wrote[/] {out_md}")
    sys.exit(0 if all(r.status.value == "ok" for r in results) else 1)


@cli.command(help="Generate a report from a past session.")
@click.option(
    "--session-id", required=True,
    help="Session UUID to generate the report for",
)
@click.option(
    "--format", "fmt", type=click.Choice(["json", "markdown", "pdf"]),
    default="pdf", show_default=True,
    help="Output format",
)
def report(session_id: str, fmt: str) -> None:
    """Generate a report from stored session results."""
    from srt.core.module import AttackResult, Risk, Status

    rows = db.query_session_results(session_id)
    if not rows:
        console.print(f"[red]No results found for session {session_id}[/]")
        sys.exit(1)

    results: list[AttackResult] = []
    for row in rows:
        results.append(AttackResult(
            module_name=row["module_name"],
            protocol=row["protocol"],
            risk=Risk(row["risk"]),
            status=Status(row["status"]),
            started_at=row.get("started_at", 0.0),
            ended_at=row.get("ended_at", 0.0),
            summary=row.get("summary", ""),
            mitre_ttp=row.get("mitre_ttp", []),
            cve=row.get("cve", []),
            artifacts=row.get("artifacts", []),
            metrics=row.get("metrics", {}),
        ))

    session_meta = {"session_id": session_id, "operator": "unknown"}
    name = f"session-{session_id[:8]}"

    if fmt == "json":
        out = write_json(results, name)
    elif fmt == "markdown":
        out = write_markdown(results, name)
    else:
        out = write_pdf(results, name, session_meta=session_meta)
        if out is None:
            console.print("[yellow]PDF generation unavailable (missing weasyprint)[/]")
            console.print("[yellow]Falling back to markdown...[/]")
            out = write_markdown(results, name)

    console.print(f"[green]wrote[/] {out}")


@cli.command(help="Start the tactical web platform (FastAPI + uvicorn).")
@click.option("--host", default="0.0.0.0", show_default=True, help="Bind address")
@click.option("--port", default=8080, type=int, show_default=True, help="Bind port")
@click.option("--reload", "do_reload", is_flag=True, help="Enable auto-reload for development")
def web(host: str, port: int, do_reload: bool) -> None:
    """Launch the SRT tactical web platform."""
    import uvicorn

    uvicorn.run(
        "srt.web.app:create_app",
        host=host,
        port=port,
        reload=do_reload,
        factory=True,
    )


if __name__ == "__main__":
    cli()

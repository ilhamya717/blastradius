"""Combine dependency, vulnerability, and reachability data into a report."""
from __future__ import annotations

from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

from .callgraph import ProjectGraph, all_users, find_reachable_users
from .scanner import Dependency
from .vulndb import Vulnerability

console = Console()


@dataclass
class BlastRadiusEntry:
    dependency: Dependency
    module: str
    vulns: list[Vulnerability]
    total_users: int
    reachable_users: list[str]  # qualnames reachable from an entrypoint

    @property
    def severity(self) -> str:
        if not self.vulns:
            return "none"
        if self.reachable_users:
            return "critical"      # vulnerable AND reachable from user-facing code
        if self.total_users:
            return "moderate"      # vulnerable and used, but not provably reachable
        return "low"               # vulnerable but declared/unused in scanned code


def build_report(deps: list[Dependency], graph: ProjectGraph) -> list[BlastRadiusEntry]:
    from .vulndb import query_vulnerabilities

    entries = []
    for dep in deps:
        vulns: list[Vulnerability] = []
        try:
            vulns = query_vulnerabilities(dep.name, dep.version)
        except RuntimeError as exc:
            console.print(f"[yellow]warn:[/yellow] {exc}")

        for module in dep.top_level_modules:
            users = all_users(graph, module)
            reachable = find_reachable_users(graph, module)
            entries.append(
                BlastRadiusEntry(
                    dependency=dep,
                    module=module,
                    vulns=vulns,
                    total_users=len(users),
                    reachable_users=[fn.qualname for fn in reachable],
                )
            )
    # sort: critical first
    order = {"critical": 0, "moderate": 1, "low": 2, "none": 3}
    entries.sort(key=lambda e: (order[e.severity], -len(e.vulns)))
    return entries


def print_report(entries: list[BlastRadiusEntry]) -> None:
    table = Table(title="Blast Radius Report", show_lines=False)
    table.add_column("Severity", style="bold")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Known Vulns")
    table.add_column("Used in project?")
    table.add_column("Reachable from entrypoint?")

    style_map = {
        "critical": "bold red",
        "moderate": "yellow",
        "low": "dim",
        "none": "green",
    }

    for e in entries:
        if e.severity == "none":
            continue  # skip non-vulnerable deps in the printed table for signal-to-noise
        vuln_str = ", ".join(v.id for v in e.vulns[:3]) + (f" (+{len(e.vulns) - 3} more)" if len(e.vulns) > 3 else "")
        used_str = f"{e.total_users} function(s)" if e.total_users else "no"
        reach_str = "\n".join(e.reachable_users[:3]) if e.reachable_users else "not proven reachable"
        table.add_row(
            f"[{style_map[e.severity]}]{e.severity.upper()}[/{style_map[e.severity]}]",
            e.dependency.name,
            e.dependency.version or "?",
            vuln_str or "-",
            used_str,
            reach_str,
        )

    console.print(table)

    n_critical = sum(1 for e in entries if e.severity == "critical")
    if n_critical:
        console.print(f"\n[bold red]{n_critical} package(s) have vulnerable code reachable from an entrypoint.[/bold red]")
    else:
        console.print("\n[green]No vulnerable dependency was proven reachable from a detected entrypoint.[/green]")

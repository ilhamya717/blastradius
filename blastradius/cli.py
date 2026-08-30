from __future__ import annotations

import argparse
from pathlib import Path

from .callgraph import build_project_graph
from .report import build_report, print_report
from .scanner import discover_dependencies


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="blastradius",
        description="Reachability-aware supply-chain risk scanner for Python projects.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Project root to scan (default: current dir)")
    args = parser.parse_args()

    project_root = Path(args.path).resolve()
    if not project_root.exists():
        raise SystemExit(f"Path not found: {project_root}")

    print(f"Scanning {project_root} ...")
    deps = discover_dependencies(project_root)
    print(f"Found {len(deps)} declared dependencies.")

    graph = build_project_graph(project_root)
    print(f"Parsed {len(graph.funcs)} functions across the project.")

    entries = build_report(deps, graph)
    print_report(entries)


if __name__ == "__main__":
    main()

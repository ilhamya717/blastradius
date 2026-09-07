from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .baseline import build_baseline, diff_against_baseline, load_baseline, save_baseline
from .callgraph import build_project_graph
from .report import build_report, print_report, sort_entries, to_json
from .scanner import discover_dependencies, discover_js_dependencies

_SEVERITY_RANK = {"none": 0, "low": 1, "moderate": 2, "critical": 3}
_MANIFEST_NAMES = ("requirements.txt", "pyproject.toml", "package.json")
_SKIP_DIR_NAMES = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


def _find_manifest_roots(root: Path) -> list[Path]:
    """`root` itself if it has a manifest, plus any immediate subdirectory
    that has one -- covers the common backend/ + frontend/ monorepo split
    without a full recursive search."""
    roots = []
    if any((root / name).exists() for name in _MANIFEST_NAMES):
        roots.append(root)
    if root.is_dir():
        for child in sorted(root.iterdir()):
            if child.is_dir() and child.name not in _SKIP_DIR_NAMES and not child.name.startswith("."):
                if any((child / name).exists() for name in _MANIFEST_NAMES):
                    roots.append(child)
    return roots


def _scan_root(root: Path, *, use_cache: bool, log) -> list:
    entries = []

    py_deps = discover_dependencies(root)
    if py_deps or (root / "requirements.txt").exists() or (root / "pyproject.toml").exists():
        log(f"Found {len(py_deps)} declared Python dependencies.")
        py_graph = build_project_graph(root)
        log(f"Parsed {len(py_graph.funcs)} Python functions.")
        entries += build_report(py_deps, py_graph, use_cache=use_cache)

    if (root / "package.json").exists():
        js_deps = discover_js_dependencies(root)
        log(f"Found {len(js_deps)} declared JS/TS dependencies.")
        try:
            from .js_callgraph import NodeNotFoundError, build_js_project_graph
            js_graph = build_js_project_graph(root)
            log(f"Parsed {len(js_graph.funcs)} JS/TS functions.")
            entries += build_report(js_deps, js_graph, use_cache=use_cache)
        except NodeNotFoundError as exc:
            log(f"[skipping JS/TS analysis] {exc}")

    return entries


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="blastradius",
        description="Reachability-aware supply-chain risk scanner (Python; JS/TS if Node.js is available).",
    )
    parser.add_argument("path", nargs="?", default=".", help="Project root to scan (default: current dir)")
    parser.add_argument(
        "--output", choices=["table", "json"], default="table",
        help="Report format. 'table' is human-readable (default); 'json' is untruncated, for tooling/CI.",
    )
    parser.add_argument(
        "--out", type=str, default=None,
        help="Write the report to this file instead of stdout (useful with --output json).",
    )
    parser.add_argument(
        "--fail-on", choices=["critical", "moderate", "low"], default=None,
        help="Exit with code 1 if any finding reaches this severity or higher. Intended for CI.",
    )
    parser.add_argument(
        "--baseline", type=str, default=None,
        help="Path to a baseline JSON snapshot (see --update-baseline). When given, the report is "
             "diffed against it and a change summary (new findings / new CVEs / escalations / "
             "resolved) is printed.",
    )
    parser.add_argument(
        "--update-baseline", action="store_true",
        help="Write the current report to --baseline as the new accepted snapshot, instead of diffing.",
    )
    parser.add_argument(
        "--fail-on-new", action="store_true",
        help="Exit with code 1 if the diff against --baseline shows new/escalated risk. Requires "
             "--baseline (and is ignored with --update-baseline). Use instead of --fail-on in CI "
             "once a baseline exists, so review is only demanded for what actually changed.",
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="Bypass the on-disk OSV.dev response cache and query fresh for every dependency.",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress progress messages (still prints the report).")
    args = parser.parse_args()

    if args.fail_on_new and not args.baseline:
        parser.error("--fail-on-new requires --baseline")

    project_root = Path(args.path).resolve()
    if not project_root.exists():
        raise SystemExit(f"Path not found: {project_root}")

    def log(msg: str) -> None:
        if not args.quiet:
            print(msg, file=sys.stderr)

    log(f"Scanning {project_root} ...")

    manifest_roots = _find_manifest_roots(project_root)
    if not manifest_roots:
        print(
            f"WARNING: no requirements.txt, pyproject.toml, or package.json found in "
            f"{project_root} or its immediate subdirectories. Nothing was scanned -- "
            f"the report below is empty because of that, NOT because your dependencies "
            f"are clean. If this is a monorepo with manifests nested deeper (e.g. "
            f"packages/*/package.json), scan each subproject directly.",
            file=sys.stderr,
        )

    entries = []
    for root in manifest_roots:
        if root != project_root:
            log(f"\n-- subproject: {root.relative_to(project_root)} --")
        entries += _scan_root(root, use_cache=not args.no_cache, log=log)

    sort_entries(entries)

    if args.output == "json":
        rendered = to_json(entries)
        if args.out:
            Path(args.out).write_text(rendered, encoding="utf-8")
            log(f"Wrote JSON report to {args.out}")
        else:
            print(rendered)
    else:
        if args.out:
            from rich.console import Console
            with open(args.out, "w", encoding="utf-8") as f:
                file_console = Console(file=f, width=200)
                print_report(entries, console=file_console)
            log(f"Wrote table report to {args.out}")
        else:
            print_report(entries)

    if args.baseline:
        baseline_path = Path(args.baseline)
        if args.update_baseline:
            snapshot = build_baseline(entries)
            save_baseline(baseline_path, snapshot)
            log(f"\nBaseline written to {baseline_path} ({len(snapshot['packages'])} package(s)).")
        else:
            if not baseline_path.exists():
                raise SystemExit(
                    f"Baseline not found: {baseline_path}\n"
                    f"Create one first with: blastradius {args.path} --baseline {args.baseline} --update-baseline"
                )
            baseline = load_baseline(baseline_path)
            diff = diff_against_baseline(entries, baseline)
            lines = diff.summary_lines()
            if lines:
                log("\n--- Baseline diff ---")
                for line in lines:
                    log(line)
            else:
                log("\nNo change vs. baseline.")

            if args.fail_on_new and diff.has_new_risk:
                log("\nFAIL: new or escalated risk vs. baseline.")
                sys.exit(1)

    if args.fail_on:
        threshold = _SEVERITY_RANK[args.fail_on]
        worst = max((_SEVERITY_RANK[e.severity] for e in entries), default=0)
        if worst >= threshold:
            log(f"\nFAIL: found severity >= '{args.fail_on}'.")
            sys.exit(1)


if __name__ == "__main__":
    main()

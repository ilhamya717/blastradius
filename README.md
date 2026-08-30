# blastradius

**Reachability-aware supply-chain risk scanner.**

Most SCA tools (Dependabot, Snyk, `pip-audit`) tell you *"package X has CVE-Y"* —
full stop. That's noisy: most flagged CVEs live in code paths your project
never touches. `blastradius` adds the missing question: **is the vulnerable
package actually used, and is that usage reachable from a user-facing
entrypoint** (an HTTP route, a CLI command, `if __name__ == "__main__"`)?

## How it works

1. **Scan** `requirements.txt` / `pyproject.toml` for declared dependencies
   and resolve installed versions via `importlib.metadata`.
2. **Static analysis** (`ast`, no execution) over your project's `.py` files:
   - which functions import/use which dependency,
   - a heuristic call graph between your own functions,
   - a heuristic entrypoint detector (Flask/FastAPI routes, Click/argparse
     CLIs, `if __name__ == "__main__"` blocks, functions named `main`).
3. **Reachability**: BFS from every detected entrypoint through the call
   graph — a dependency's usage is "reachable" if some entrypoint can reach
   the function that touches it.
4. **Vulnerability lookup** via [OSV.dev](https://osv.dev) for each
   package+version.
5. **Report**: severity is driven by reachability, not just CVE existence —
   `critical` (vulnerable + reachable from an entrypoint) down to `low`
   (vulnerable but declared/unused in the scanned code).

## Install

```
cd blastradius
pip install -e .
```

## Usage

```
blastradius /path/to/project
```

## Limitations (read before trusting the output)

This is a **heuristic v0**, not a sound analysis:
- No type inference. Call graph resolution is by bare function name, and
  prefers a same-file match before falling back to a project-wide one, but
  two same-named functions in the same file/class scope can still collide.
- Module-level ("top of file") code is credited as reachable if its file
  is transitively imported from a file containing an entrypoint — this
  assumes every local `import`/`from` actually executes that file's
  top-level code, which is true in normal Python but not under conditional
  or lazy/deferred imports (e.g. inside a `try/except ImportError`, or an
  import gated by a runtime flag).
- OSV.dev vulnerability data is package-level, not function-level — "used"
  means the module was referenced anywhere in a reachable function or at
  module scope, not that the specific vulnerable function was called.
- Dynamic dispatch (`getattr`, decorators that wrap unpredictably, plugin
  systems) is invisible to static `ast` analysis.

Treat `critical` findings as **"investigate first"**, not "confirmed
exploitable" — and treat `low`/`moderate` as "not yet disproven", not safe.

## Roadmap ideas

- Function-level vuln matching (map OSV advisory affected ranges to
  specific patched functions when advisory data allows).
- Cross-file type-aware call resolution (e.g. via `jedi` or a proper CPG).
- JS/TS and Go ecosystem support.
- Baseline diffing: fail CI only on *new* findings vs. a stored baseline,
  not everything every run.

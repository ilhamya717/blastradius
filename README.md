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

OSV.dev lookups are cached to disk for 24h by default (`~/.cache/blastradius/osv/`,
override with `$BLASTRADIUS_CACHE_DIR`) — a repeat scan of the same project
is typically 10-20x faster and doesn't re-hit OSV for every dependency
every run. Pass `--no-cache` to always query fresh.

JSON output for tooling, and a `--fail-on` severity gate:

```
blastradius /path/to/project --output json --out report.json
blastradius /path/to/project --fail-on critical   # exit 1 if any CRITICAL finding
```

### CI mode: baseline diffing

`--fail-on` re-fails on the same accepted-risk findings every run. Once a
project has a known set of findings you've triaged and accepted (or just
haven't gotten to yet), gate on **new** risk instead:

```
# once, to accept the current state:
blastradius . --baseline .blastradius-baseline.json --update-baseline

# in CI, every run after:
blastradius . --baseline .blastradius-baseline.json --fail-on-new
```

This fails only when something actually changed for the worse: a package
newly flagged, a new CVE disclosed on an already-flagged package, or a
severity escalation (e.g. a package became reachable that wasn't before).
A package dropping out of the report (upgraded/removed) is reported as
`RESOLVED`, never a failure. Commit the baseline file alongside your code
and update it deliberately (as its own reviewed change) when you've
looked at a new finding and decided to accept it.

## Limitations (read before trusting the output)

This is a **heuristic v0**, not a sound analysis:
- **No type inference — call resolution is by bare name, not by object.**
  `obj1.process()` and `obj2.process()` look identical to this analysis.
  Resolution prefers a same-file candidate over a project-wide one, which
  handles the common case (an entrypoint calling a same-file helper), but
  when an entrypoint calls a bare name with **no same-file candidate at
  all**, every same-named function *project-wide* gets swept in as a false
  positive — see `test_KNOWN_LIMITATION_*` in `tests/test_callgraph.py` for
  a reproduction and a quantified example (the false-positive count scales
  linearly with how many unrelated functions share that name). This is the
  tool's biggest source of over-approximation in codebases with common,
  unqualified method names (`get`/`post`/`handle`/`run`/`process`/...) —
  there's no fix for it without real type inference, so treat a CRITICAL
  finding whose only reachable-from path is a long, unfamiliar call chain
  as worth a second look, not gospel.
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

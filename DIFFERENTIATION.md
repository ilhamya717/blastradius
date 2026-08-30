# How this differs from Snyk / Dependabot / pip-audit

Short version: they answer **"does this package have a CVE?"** blastradius
answers **"can an attacker actually reach the vulnerable code?"** Those are
different questions, and the second one is the one that determines whether
you should drop everything to patch tonight or file it for next sprint.

## The problem with existence-based scanning

Dependabot/Snyk/pip-audit work the same way: resolve your dependency tree,
match package+version against a CVE database, alert on every match. This is
necessary but not sufficient — it treats every match as equally urgent
regardless of whether your code ever executes the vulnerable path.

In a real audit (see below), 18 flagged dependencies is not 18 things to
investigate this week. It's 2.

This isn't Python-specific: the same reachability model applies to JS/TS
projects (Express/Koa/Fastify route detection via `@babel/parser`), so a
Node.js monorepo gets the same "2 out of 18" treatment, not just Python
services.

## What "reachability-aware" actually means here

Three independent signals, all from static analysis (no code execution):

1. **Is the package used at all** in the code we scanned — imported and
   referenced by name — or just declared and never touched (common with
   transitive dependencies)?
2. **Is that usage reachable from an entrypoint** — an HTTP route, a CLI
   command, a `__main__` block — via a best-effort call graph (including
   module-level/top-of-file code reached transitively via the import
   graph)?
3. **Is the installed/pinned version actually confirmed**, or are we
   matching CVEs against an unpinned dependency (which can span every
   historical version and shouldn't be allowed to inflate to CRITICAL on
   its own)?

Severity is a function of all three, not just "CVE exists":

| Reachable from entrypoint | Used in code | Version confirmed | Severity |
|---|---|---|---|
| Yes | Yes | Yes | **CRITICAL** |
| No | Yes | Yes | MODERATE |
| No | No | — | LOW |
| Yes/No | Yes/No | **No** | capped at MODERATE |

## This is not a hypothetical — real numbers from real projects

We ran it against three open-source Python projects to validate the claim,
not just assert it:

- **DVPWA** (Damn Vulnerable Python Web App): 18 declared dependencies, 4
  had known CVEs. Of those 4, only **2** (`aiohttp`, `jinja2`) were
  reachable from an actual route handler / app bootstrap — confirmed by
  reading the source, not just trusting the tool. The other 2
  (`pyyaml`, `idna`) had real CVEs too, but were transitive-only (never
  directly imported by the app's own code) and correctly demoted.
- **Django** (~2,900 files, 28k functions): a naive existence-based scan
  and an early, less-precise version of this tool's own entrypoint
  detection both produced a false CRITICAL for `sqlparse` — traced back to
  a bug where `@patch` (`unittest.mock`, from test files) was
  misclassified as an HTTP-PATCH route decorator. Fixing that collapsed a
  bogus reachability chain and correctly downgraded the finding. Existence-
  based scanning has no equivalent self-correction mechanism — it would
  have flagged `sqlparse` as high-priority regardless, forever.
- **Flask** itself (83 files): zero findings, because its own dependencies
  are current. Fast (~7s) to confirm that, not just "trust us."
- **Express.js** itself (JS/TS side, 141 files / 3,194 functions): also
  zero findings for the same reason — current dependencies, confirmed in
  ~44s rather than assumed. A synthetic sample app pinned to
  `lodash@4.17.4` + `express@4.18.2` (both with real, known CVEs)
  correctly separated a route handler that actually called the vulnerable
  code (CRITICAL) from a dead-code function that imported the same
  package but was never called from anywhere (excluded from the
  reachable set) — the JS/TS analysis draws the same distinction the
  Python side does, not a weaker approximation of it.

## What we are explicitly not claiming

- Not a replacement for a CVE database — we use OSV.dev for the actual
  vulnerability data. We're a **prioritization layer on top of it**.
- Not sound. This is static, heuristic analysis (Python's `ast`, no type
  inference). It can both miss a real reachable path (dynamic dispatch,
  `getattr`, plugin systems) and flag a false one (bare-name call
  resolution without object identity — [documented and tested
  explicitly](README.md#limitations-read-before-trusting-the-output),
  not hand-waved).
- A LOW/MODERATE finding is "lower confidence of exploitability right
  now," not "safe" — the underlying CVE is still real. Don't use this to
  justify *not* patching, only to decide *what order* to patch in.

## The actual pitch, one sentence

Existence-based SCA tells you what's broken. This tells you what's broken
**and reachable**, so a team with limited attention spends it on the 2
findings that matter instead of triaging all 18 with equal urgency.

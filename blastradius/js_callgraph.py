"""JS/TS static analysis, mirroring callgraph.py's model exactly so
report.py / baseline.py / the CLI work unchanged regardless of language.

Parsing itself is delegated to a small Node.js helper (js_helper/parse.js)
using @babel/parser, since there's no mature pure-Python JS/TS/JSX parser
worth trusting here. This module only does the traversal -- same division
of labor as callgraph.py using Python's own `ast` module directly.

Requires Node.js on PATH (checked explicitly; raises a clear error if
missing rather than failing deep inside a subprocess call).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .callgraph import FuncNode, ProjectGraph

JS_HELPER_DIR = Path(__file__).parent / "js_helper"
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

# Express/Koa/Fastify-style route registration: app.get('/x', handler) etc.
# Attribute-based (like Python's decorator match) -- doesn't care what the
# object is named (app, router, api, ...).
ENTRYPOINT_METHODS = {"get", "post", "put", "delete", "patch", "all", "route", "use"}


class NodeNotFoundError(RuntimeError):
    pass


def _require_node() -> str:
    node = shutil.which("node")
    if not node:
        raise NodeNotFoundError(
            "JS/TS scanning requires Node.js on PATH (used to run @babel/parser). "
            "Install Node.js, or scan a Python project instead."
        )
    return node


def _parse_files(files: list[Path]) -> dict[str, dict]:
    """Batch-parse files via the Node helper; returns {abs_path_str: ast_or_None}."""
    if not files:
        return {}
    node = _require_node()
    proc = subprocess.run(
        [node, str(JS_HELPER_DIR / "parse.js")],
        input="\n".join(str(f) for f in files),
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=str(JS_HELPER_DIR),
        timeout=120,
    )
    results: dict[str, dict] = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "ast" in entry:
            results[entry["file"]] = entry["ast"]
        # entries with "error" (syntax errors, unsupported syntax) are just skipped,
        # mirroring how callgraph.py skips a .py file that fails to parse.
    return results


def _iter_children(node):
    """Babel AST nodes are plain dicts; walk every dict/list-valued field."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("loc", "start", "end", "range", "leadingComments", "trailingComments"):
                continue
            yield from _iter_children(value)
        return
    if isinstance(node, list):
        for item in node:
            yield from _iter_children(item)
        return
    if isinstance(node, dict) and node.get("type"):
        yield node


def _member_name(node: dict) -> str | None:
    """For a MemberExpression, the property name if it's a plain `.attr` access."""
    if node.get("computed"):
        return None
    prop = node.get("property") or {}
    return prop.get("name")


def _callee_name(callee: dict) -> str | None:
    if callee.get("type") == "Identifier":
        return callee.get("name")
    if callee.get("type") == "MemberExpression":
        return _member_name(callee)
    return None


class _JSFileVisitor:
    def __init__(self, file: str, graph: ProjectGraph):
        self.file = file
        self.graph = graph
        self.import_alias_to_module: dict[str, str] = {}  # local name -> raw import specifier

        module_node = FuncNode(qualname=f"{file}:__module__", file=file, lineno=1, is_module_scope=True)
        graph.funcs[module_node.qualname] = module_node
        self._func_stack: list[FuncNode] = [module_node]
        self._anon_counter = 0

    def _fresh_anon_name(self) -> str:
        self._anon_counter += 1
        return f"<anonymous {self._anon_counter}>"

    def _push_func(self, name: str, lineno: int) -> FuncNode:
        qualname = f"{self.file}:{name}"
        # two anonymous/duplicate-named functions at the same nominal name are
        # disambiguated by line number, same spirit as Python's class-scoping fix
        if qualname in self.graph.funcs:
            qualname = f"{self.file}:{name}@{lineno}"
        fn = FuncNode(qualname=qualname, file=self.file, lineno=lineno)
        self.graph.funcs[qualname] = fn
        self.graph.by_bare_name.setdefault(name, set()).add(qualname)
        self._func_stack.append(fn)
        return fn

    def _pop_func(self) -> None:
        self._func_stack.pop()

    # -- traversal -----------------------------------------------------

    def visit(self, node) -> None:
        if isinstance(node, list):
            for item in node:
                self.visit(item)
            return
        if not isinstance(node, dict) or "type" not in node:
            return

        t = node["type"]
        handler = getattr(self, f"_on_{t}", None)
        if handler:
            handler(node)
        else:
            self._generic(node)

    def _generic(self, node: dict) -> None:
        for key, value in node.items():
            if key in ("loc", "start", "end", "range", "leadingComments", "trailingComments"):
                continue
            self.visit(value)

    # imports / requires

    def _on_ImportDeclaration(self, node: dict) -> None:
        source = (node.get("source") or {}).get("value")
        if source:
            for spec in node.get("specifiers", []):
                local = (spec.get("local") or {}).get("name")
                if local:
                    self.import_alias_to_module[local] = source
        self._generic(node)

    def _on_CallExpression(self, node: dict) -> None:
        callee = node.get("callee") or {}
        fname = _callee_name(callee)

        if callee.get("type") == "Identifier" and callee.get("name") == "require":
            args = node.get("arguments") or []
            if args and args[0].get("type") == "StringLiteral":
                self._func_stack[-1].uses_modules.add(args[0]["value"])

        if fname:
            self._func_stack[-1].calls.add(fname)

        # Visit the whole callee subtree (not just, say, `.object` for a
        # MemberExpression) so a nested/chained callee -- e.g. the inner
        # CallExpression in `_.template(x)(y)` -- still gets walked instead
        # of silently dropped.
        self.visit(callee)

        # Express-style registration: app.get('/x', handler) / router.use(handler).
        # Handled here (rather than via the default _generic descent) so an
        # inline function literal argument can be marked as an entrypoint at
        # the moment its FuncNode is created -- by the time _generic() would
        # otherwise visit it, we've lost the "this is a route arg" context.
        is_registration = callee.get("type") == "MemberExpression" and _member_name(callee) in ENTRYPOINT_METHODS
        for arg in node.get("arguments", []):
            if is_registration and arg.get("type") == "Identifier":
                self._mark_entrypoint_by_bare_name(arg["name"])
                self.visit(arg)
            elif is_registration and arg.get("type") in ("FunctionExpression", "ArrowFunctionExpression"):
                name = (arg.get("id") or {}).get("name") or self._fresh_anon_name()
                lineno = (arg.get("loc") or {}).get("start", {}).get("line", 0)
                fn = self._push_func(name, lineno)
                fn.is_entrypoint = True
                fn.entrypoint_reason = "inline route handler"
                for child_key in ("params", "body"):
                    self.visit(arg.get(child_key))
                self._pop_func()
            else:
                self.visit(arg)

    def _mark_entrypoint_by_bare_name(self, name: str) -> None:
        candidates = self.graph.by_bare_name.get(name, ())
        same_file = [qn for qn in candidates if self.graph.funcs[qn].file == self.file]
        for qn in (same_file or candidates):
            fn = self.graph.funcs[qn]
            if not fn.is_entrypoint:
                fn.is_entrypoint = True
                fn.entrypoint_reason = "referenced as a route handler"

    # functions

    def _on_FunctionDeclaration(self, node: dict) -> None:
        name = (node.get("id") or {}).get("name") or self._fresh_anon_name()
        self._handle_function_body(node, name)

    def _on_ClassMethod(self, node: dict) -> None:
        key = node.get("key") or {}
        name = key.get("name") or key.get("value") or self._fresh_anon_name()
        self._handle_function_body(node, name)

    def _on_ObjectMethod(self, node: dict) -> None:
        key = node.get("key") or {}
        name = key.get("name") or key.get("value") or self._fresh_anon_name()
        self._handle_function_body(node, name)

    def _handle_function_body(self, node: dict, name: str) -> None:
        lineno = (node.get("loc") or {}).get("start", {}).get("line", 0)
        fn = self._push_func(name, lineno)
        for child_key in ("params", "body"):
            self.visit(node.get(child_key))
        self._pop_func()

    def _on_ArrowFunctionExpression(self, node: dict) -> None:
        name = self._fresh_anon_name()
        self._handle_function_body(node, name)

    def _on_FunctionExpression(self, node: dict) -> None:
        name = (node.get("id") or {}).get("name") or self._fresh_anon_name()
        self._handle_function_body(node, name)

    # a `const handler = () => {...}` / `const handler = function () {...}`
    # binds the function to a *bare name* other than what it'd otherwise get
    # -- rename the just-created node's registration so bare-name call
    # resolution (and route-registration-by-name) can find it as `handler`.
    def _on_VariableDeclarator(self, node: dict) -> None:
        init = node.get("init") or {}
        var_name = (node.get("id") or {}).get("name")

        # `const _ = require("lodash")` -- without this, only the require()
        # call site itself (often at module scope) registers as a "use";
        # every later `_.merge(...)` reference inside a function body
        # wouldn't, since Identifier lookups depend on this alias mapping
        # existing. Destructured requires (`const { merge } = require(...)`)
        # aren't handled here -- id.type is ObjectPattern, not Identifier.
        if (
            var_name
            and init.get("type") == "CallExpression"
            and (init.get("callee") or {}).get("type") == "Identifier"
            and (init.get("callee") or {}).get("name") == "require"
        ):
            args = init.get("arguments") or []
            if args and args[0].get("type") == "StringLiteral":
                self.import_alias_to_module[var_name] = args[0]["value"]

        if var_name and init.get("type") in ("FunctionExpression", "ArrowFunctionExpression"):
            lineno = (init.get("loc") or {}).get("start", {}).get("line", 0)
            fn = self._push_func(var_name, lineno)
            for child_key in ("params", "body"):
                self.visit(init.get(child_key))
            self._pop_func()
            return
        self._generic(node)

    def _on_Identifier(self, node: dict) -> None:
        name = node.get("name")
        if name and name in self.import_alias_to_module:
            self._func_stack[-1].uses_modules.add(self.import_alias_to_module[name])


def build_js_project_graph(project_root: Path, exclude_dirs: set[str] | None = None) -> ProjectGraph:
    # must be absolute: file paths are handed to the Node subprocess, which
    # runs with cwd=JS_HELPER_DIR -- a relative project_root would resolve
    # against the wrong directory there and silently fail to parse anything.
    project_root = project_root.resolve()
    exclude_dirs = exclude_dirs or {".git", "node_modules", "dist", "build", ".next", "coverage"}
    graph = ProjectGraph()

    files = [
        f for f in project_root.rglob("*")
        if f.suffix.lower() in JS_EXTENSIONS and not any(part in exclude_dirs for part in f.parts)
    ]
    asts = _parse_files(files)

    if files and not asts:
        # Every file failed to parse -- almost certainly a systemic problem
        # (wrong cwd, Node/babel install issue) rather than N unrelated
        # syntax errors. Surface it instead of silently returning an empty
        # graph, which for a security tool would read as "nothing to see
        # here" rather than "the scan didn't actually run."
        import warnings
        warnings.warn(
            f"blastradius: 0/{len(files)} JS/TS files parsed successfully -- "
            f"results are almost certainly incomplete or empty. Check that "
            f"Node.js can run {JS_HELPER_DIR / 'parse.js'}.",
            stacklevel=2,
        )

    for f in files:
        ast_tree = asts.get(str(f))
        if ast_tree is None:
            continue
        rel = str(f.relative_to(project_root))
        _JSFileVisitor(rel, graph).visit(ast_tree.get("program", {}))

    return graph

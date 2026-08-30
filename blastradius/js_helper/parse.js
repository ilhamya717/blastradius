#!/usr/bin/env node
/**
 * Reads a list of file paths on stdin (one per line), parses each with
 * @babel/parser (JS/JSX/TS/TSX), and writes one JSON object per line to
 * stdout: {"file": "<path>", "ast": <babel-ast>} or {"file": "<path>", "error": "..."}.
 *
 * Kept deliberately dumb: no traversal logic here. The Python side
 * (blastradius/js_callgraph.py) walks the AST -- this script's only job is
 * "give me the tree," mirroring how build_project_graph() uses Python's
 * own `ast` module directly for .py files.
 */
const fs = require("fs");
const readline = require("readline");
const parser = require("@babel/parser");

function parseOne(filePath) {
  const isTS = /\.tsx?$/i.test(filePath);
  const isJSX = /\.[jt]sx$/i.test(filePath) || !isTS; // allow JSX in plain .js too (common in React codebases)
  const source = fs.readFileSync(filePath, "utf-8");
  const plugins = ["decorators-legacy", "classProperties", "classPrivateProperties", "optionalChaining", "nullishCoalescingOperator"];
  if (isTS) plugins.push("typescript");
  if (isJSX) plugins.push("jsx");
  const ast = parser.parse(source, {
    sourceType: "module",
    allowImportExportEverywhere: true,
    allowReturnOutsideFunction: true,
    errorRecovery: true,
    plugins,
  });
  return ast;
}

const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on("line", (line) => {
  const filePath = line.trim();
  if (!filePath) return;
  try {
    const ast = parseOne(filePath);
    process.stdout.write(JSON.stringify({ file: filePath, ast }) + "\n");
  } catch (err) {
    process.stdout.write(JSON.stringify({ file: filePath, error: String(err && err.message || err) }) + "\n");
  }
});

#!/usr/bin/env node
// Reads file paths on stdin (one per line), parses each with @babel/parser
// (JS/JSX/TS/TSX), writes one JSON line per file to stdout:
// {"file": ..., "ast": ...} or {"file": ..., "error": ...}. No traversal
// here -- js_callgraph.py walks the AST on the Python side.
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

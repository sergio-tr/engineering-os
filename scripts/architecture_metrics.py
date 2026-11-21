#!/usr/bin/env python3
"""AST-based architecture and complexity baseline (stdlib only)."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


ROOT = Path(__file__).resolve().parents[1] / "src" / "engineering_os"


def _param_count(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    args = node.args
    n = (
        len(args.posonlyargs)
        + len(args.args)
        + len(args.kwonlyargs)
        + (1 if args.vararg else 0)
        + (1 if args.kwarg else 0)
    )
    if args.args and args.args[0].arg in {"self", "cls"}:
        n -= 1
    return n


def _complexity(node: ast.AST) -> int:
    """Approximate cyclomatic complexity (decision points + 1)."""
    score = 1
    for child in ast.walk(node):
        if isinstance(
            child,
            (
                ast.If,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.ExceptHandler,
                ast.With,
                ast.AsyncWith,
                ast.Assert,
                ast.comprehension,
            ),
        ):
            score += 1
        elif isinstance(child, ast.BoolOp):
            score += max(0, len(child.values) - 1)
    return score


def analyze() -> Dict[str, Any]:
    modules: List[Dict[str, Any]] = []
    long_funcs: List[Tuple[int, int, int, str]] = []
    high_params: List[Tuple[int, str]] = []
    for path in sorted(ROOT.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        lines = text.count("\n") + (0 if text.endswith("\n") else 1)
        classes = sum(isinstance(n, ast.ClassDef) for n in tree.body)
        funcs = 0
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs += 1
                params = _param_count(node)
                end = getattr(node, "end_lineno", node.lineno) or node.lineno
                length = end - node.lineno + 1
                cplx = _complexity(node)
                rel = f"{path.relative_to(ROOT.parent)}:{node.name}"
                if length >= 80:
                    long_funcs.append((length, params, cplx, rel))
                if params >= 8:
                    high_params.append((params, rel))
        modules.append(
            {
                "path": str(path.relative_to(ROOT.parent)),
                "lines": lines,
                "classes": classes,
                "functions": funcs,
            }
        )
    modules.sort(key=lambda m: m["lines"], reverse=True)
    long_funcs.sort(reverse=True)
    high_params.sort(reverse=True)
    return {
        "python_files": len(modules),
        "total_lines": sum(m["lines"] for m in modules),
        "largest_modules": modules[:20],
        "longest_functions": [
            {"lines": a, "params": b, "complexity": c, "name": d}
            for a, b, c, d in long_funcs[:25]
        ],
        "high_parameter_functions": [
            {"params": a, "name": b} for a, b in high_params[:25]
        ],
    }


def main() -> int:
    report = analyze()
    out = Path(__file__).resolve().parents[1] / "docs" / "architecture" / "metrics-baseline.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"wrote": str(out), "summary": {
        "python_files": report["python_files"],
        "total_lines": report["total_lines"],
        "top_module": report["largest_modules"][0] if report["largest_modules"] else None,
        "longest_function": report["longest_functions"][0] if report["longest_functions"] else None,
    }}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate Engineering OS canonical contract schemas and examples.

Baseline checks use the Python standard library only.
If the optional local ``jsonschema`` package is already installed, examples are
also validated against Draft 2020-12 schemas.

This script performs no network access, installs nothing, and writes no files.
A successful baseline run is NOT proof of complete JSON Schema conformance
unless the optional jsonschema validation section reports PASS.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "docs" / "contracts"
SCHEMAS = CONTRACTS / "schemas"
EXAMPLES = CONTRACTS / "examples"

CONTRACT_VERSION = "0.1.0"
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"

CONTRACTS_SPEC = (
    {
        "stem": "project-profile",
        "kind": "ProjectProfile",
        "required": (
            "kind",
            "contract_version",
            "project_id",
            "display_name",
            "repository",
            "isolation",
            "execution_policy",
            "scope",
        ),
    },
    {
        "stem": "agent-profile",
        "kind": "AgentProfile",
        "required": (
            "kind",
            "contract_version",
            "agent_id",
            "role_id",
            "assigned_project_ids",
            "capabilities",
            "tool_access",
            "model_selection_policy",
            "human_escalation",
        ),
    },
    {
        "stem": "execution-contract",
        "kind": "ExecutionContract",
        "required": (
            "kind",
            "contract_version",
            "execution_id",
            "project_id",
            "task_id",
            "agent_id",
            "repository",
            "expected_revision",
            "scope",
            "sandbox",
            "network_policy",
            "ceilings",
            "required_outputs",
            "git_write",
            "correlation_id",
        ),
    },
    {
        "stem": "approval-contract",
        "kind": "ApprovalContract",
        "required": (
            "kind",
            "contract_version",
            "approval_id",
            "project_id",
            "requested_action",
            "scope",
            "requester",
            "approver",
            "decision",
            "created_at",
            "expires_at",
            "correlation_id",
            "constraints",
        ),
    },
)


class Reporter:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.checks: list[tuple[str, str, str]] = []

    def record(self, name: str, status: str, detail: str = "") -> None:
        self.checks.append((name, status, detail))
        marker = {
            "PASS": "PASS",
            "FAIL": "FAIL",
            "NOT_TESTED": "NOT_TESTED",
        }.get(status, status)
        suffix = f" — {detail}" if detail else ""
        print(f"[{marker}] {name}{suffix}")
        if status == "FAIL":
            self.failures.append(f"{name}: {detail}")


def load_json(path: Path, reporter: Reporter, label: str) -> Any | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        reporter.record(label, "FAIL", f"missing file: {path}")
    except json.JSONDecodeError as exc:
        reporter.record(label, "FAIL", f"invalid JSON in {path}: {exc}")
    except OSError as exc:
        reporter.record(label, "FAIL", f"cannot read {path}: {exc}")
    return None


def main() -> int:
    reporter = Reporter()
    print("Engineering OS contract validation")
    print(f"Repository root: {ROOT}")
    print()

    schema_docs: dict[str, Any] = {}
    example_docs: dict[str, Any] = {}

    # 1–3: existence and parse
    for spec in CONTRACTS_SPEC:
        stem = spec["stem"]
        schema_path = SCHEMAS / f"{stem}.schema.json"
        example_path = EXAMPLES / f"{stem}.example.json"

        if schema_path.is_file():
            reporter.record(f"schema exists:{stem}", "PASS", str(schema_path.relative_to(ROOT)))
        else:
            reporter.record(f"schema exists:{stem}", "FAIL", str(schema_path))

        if example_path.is_file():
            reporter.record(f"example exists:{stem}", "PASS", str(example_path.relative_to(ROOT)))
        else:
            reporter.record(f"example exists:{stem}", "FAIL", str(example_path))

        schema = load_json(schema_path, reporter, f"schema parse:{stem}")
        if schema is not None:
            reporter.record(f"schema parse:{stem}", "PASS")
            schema_docs[stem] = schema

        example = load_json(example_path, reporter, f"example parse:{stem}")
        if example is not None:
            reporter.record(f"example parse:{stem}", "PASS")
            example_docs[stem] = example

    # 4–9: structural baseline checks
    for spec in CONTRACTS_SPEC:
        stem = spec["stem"]
        kind = spec["kind"]
        schema = schema_docs.get(stem)
        example = example_docs.get(stem)
        if schema is None or example is None:
            continue

        if schema.get("$schema") == DRAFT_2020_12:
            reporter.record(f"schema draft:{stem}", "PASS", "Draft 2020-12")
        else:
            reporter.record(
                f"schema draft:{stem}",
                "FAIL",
                f"expected {DRAFT_2020_12}, got {schema.get('$schema')!r}",
            )

        schema_kind = schema.get("properties", {}).get("kind", {}).get("const")
        schema_version = schema.get("properties", {}).get("contract_version", {}).get("const")
        if schema_kind == kind and schema_version == CONTRACT_VERSION:
            reporter.record(
                f"schema discriminators:{stem}",
                "PASS",
                f"kind={kind}, contract_version={CONTRACT_VERSION}",
            )
        else:
            reporter.record(
                f"schema discriminators:{stem}",
                "FAIL",
                f"kind={schema_kind!r}, contract_version={schema_version!r}",
            )

        if not isinstance(example, dict):
            reporter.record(f"example object:{stem}", "FAIL", "example is not a JSON object")
            continue

        if example.get("kind") == kind and example.get("contract_version") == CONTRACT_VERSION:
            reporter.record(
                f"example discriminators:{stem}",
                "PASS",
                f"kind={kind}, contract_version={CONTRACT_VERSION}",
            )
        else:
            reporter.record(
                f"example discriminators:{stem}",
                "FAIL",
                f"kind={example.get('kind')!r}, contract_version={example.get('contract_version')!r}",
            )

        missing = [field for field in spec["required"] if field not in example]
        if missing:
            reporter.record(f"example required fields:{stem}", "FAIL", f"missing {missing}")
        else:
            reporter.record(f"example required fields:{stem}", "PASS")

        schema_props = set(schema.get("properties", {}))
        unexpected = sorted(set(example) - schema_props)
        if unexpected:
            reporter.record(
                f"example additionalProperties:{stem}",
                "FAIL",
                f"unexpected top-level fields: {unexpected}",
            )
        else:
            reporter.record(f"example additionalProperties:{stem}", "PASS")

        expected_schema_name = f"{stem}.schema.json"
        expected_example_name = f"{stem}.example.json"
        if (SCHEMAS / expected_schema_name).name == expected_schema_name and (
            EXAMPLES / expected_example_name
        ).name == expected_example_name:
            reporter.record(
                f"file mapping:{stem}",
                "PASS",
                f"{expected_schema_name} <-> {expected_example_name} <-> {kind}",
            )

    # 10: optional full JSON Schema validation + explicit coverage reporting
    print()
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError:
        reporter.record(
            "jsonschema package",
            "NOT_TESTED",
            "package not installed; baseline checks only",
        )
        for spec in CONTRACTS_SPEC:
            reporter.record(
                f"schema meta-validation:{spec['stem']}",
                "NOT_TESTED",
                "requires local jsonschema",
            )
            reporter.record(
                f"full schema validation:{spec['stem']}",
                "NOT_TESTED",
                "requires local jsonschema",
            )
            reporter.record(
                f"format assertion:{spec['stem']}",
                "NOT_TESTED",
                "requires local jsonschema FormatChecker",
            )
    else:
        reporter.record(
            "jsonschema package",
            "PASS",
            "available for Draft 2020-12 validation",
        )
        format_checker = FormatChecker()
        for spec in CONTRACTS_SPEC:
            stem = spec["stem"]
            schema = schema_docs.get(stem)
            example = example_docs.get(stem)
            if schema is None or example is None:
                reporter.record(
                    f"schema meta-validation:{stem}",
                    "FAIL",
                    "schema or example unavailable",
                )
                reporter.record(
                    f"full schema validation:{stem}",
                    "FAIL",
                    "schema or example unavailable",
                )
                reporter.record(
                    f"format assertion:{stem}",
                    "FAIL",
                    "schema or example unavailable",
                )
                continue
            try:
                Draft202012Validator.check_schema(schema)
                reporter.record(
                    f"schema meta-validation:{stem}",
                    "PASS",
                    "Draft202012Validator.check_schema",
                )
            except Exception as exc:  # noqa: BLE001 - report any validator failure
                reporter.record(
                    f"schema meta-validation:{stem}",
                    "FAIL",
                    f"{type(exc).__name__}: {exc}",
                )
                reporter.record(
                    f"full schema validation:{stem}",
                    "FAIL",
                    "skipped because schema meta-validation failed",
                )
                reporter.record(
                    f"format assertion:{stem}",
                    "FAIL",
                    "skipped because schema meta-validation failed",
                )
                continue

            try:
                validator = Draft202012Validator(schema)
                errors = sorted(validator.iter_errors(example), key=lambda exc: list(exc.path))
                if errors:
                    first = errors[0]
                    path = ".".join(str(part) for part in first.path) or "<root>"
                    reporter.record(
                        f"full schema validation:{stem}",
                        "FAIL",
                        f"{len(errors)} error(s); first at {path}: {first.message}",
                    )
                else:
                    reporter.record(
                        f"full schema validation:{stem}",
                        "PASS",
                        "Draft202012Validator without FormatChecker",
                    )
            except Exception as exc:  # noqa: BLE001 - report any validator failure
                reporter.record(
                    f"full schema validation:{stem}",
                    "FAIL",
                    f"{type(exc).__name__}: {exc}",
                )

            try:
                format_validator = Draft202012Validator(schema, format_checker=format_checker)
                format_errors = sorted(
                    format_validator.iter_errors(example),
                    key=lambda exc: list(exc.path),
                )
                if format_errors:
                    first = format_errors[0]
                    path = ".".join(str(part) for part in first.path) or "<root>"
                    reporter.record(
                        f"format assertion:{stem}",
                        "FAIL",
                        f"{len(format_errors)} error(s); first at {path}: {first.message}",
                    )
                else:
                    reporter.record(
                        f"format assertion:{stem}",
                        "PASS",
                        "Draft202012Validator with FormatChecker",
                    )
            except Exception as exc:  # noqa: BLE001 - report any validator failure
                reporter.record(
                    f"format assertion:{stem}",
                    "FAIL",
                    f"{type(exc).__name__}: {exc}",
                )

    print()
    pass_count = sum(1 for _, status, _ in reporter.checks if status == "PASS")
    fail_count = sum(1 for _, status, _ in reporter.checks if status == "FAIL")
    skip_count = sum(1 for _, status, _ in reporter.checks if status == "NOT_TESTED")
    print(f"Summary: PASS={pass_count} FAIL={fail_count} NOT_TESTED={skip_count}")
    print(
        "Coverage note: baseline structural checks are not a substitute for full "
        "JSON Schema validation. Meta-validation uses check_schema(); instance "
        "validation is reported separately from format assertion via FormatChecker."
    )

    if reporter.failures:
        print()
        print("Failures:")
        for item in reporter.failures:
            print(f"- {item}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

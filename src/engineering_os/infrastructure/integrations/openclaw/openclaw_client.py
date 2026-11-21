"""OpenClaw read-only CLI observation client (fixed argv, no shell)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence

from engineering_os.infrastructure.evidence import ERROR, LIVE_READ_ONLY, UNAVAILABLE


class OpenClawClientError(RuntimeError):
    def __init__(self, message: str, *, code: str = "openclaw_error") -> None:
        super().__init__(message)
        self.code = code


Runner = Callable[[Sequence[str], float, Dict[str, str]], "CommandResult"]


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    argv: List[str]


def default_runner(
    argv: Sequence[str], timeout: float, env: Dict[str, str]
) -> CommandResult:
    # Fixed argument array — never shell=True, never interpolate untrusted input.
    completed = subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        argv=list(argv),
    )


@dataclass
class OpenClawCliClient:
    """Read-only OpenClaw diagnostics via documented CLI flags."""

    binary: str = "openclaw"
    timeout_seconds: float = 15.0
    runner: Optional[Runner] = None
    which: Optional[Callable[[str], Optional[str]]] = None

    def __post_init__(self) -> None:
        self.runner = self.runner or default_runner
        self.which = self.which or shutil.which

    def _sanitized_env(self) -> Dict[str, str]:
        # Minimal env; do not pass secrets into OpenClaw probes.
        allow = {"PATH", "HOME", "LANG", "LC_ALL", "TERM", "USER", "LOGNAME"}
        return {k: v for k, v in os.environ.items() if k in allow}

    def binary_path(self) -> Optional[str]:
        assert self.which is not None
        return self.which(self.binary)

    def status_json(self) -> Dict[str, Any]:
        path = self.binary_path()
        if not path:
            return {
                "available": False,
                "evidence_class": UNAVAILABLE,
                "error": {"code": "openclaw_absent"},
            }
        argv = [path, "status", "--json"]
        return self._run_json(argv, label="status")

    def gateway_status(self) -> Dict[str, Any]:
        path = self.binary_path()
        if not path:
            return {
                "available": False,
                "evidence_class": UNAVAILABLE,
                "error": {"code": "openclaw_absent"},
                "rpc_required": True,
            }
        # Documented Owner request: gateway status with RPC requirement.
        # Prefer JSON when the installed CLI supports it; still fixed argv only.
        argv = [path, "gateway", "status", "--require-rpc"]
        assert self.runner is not None
        try:
            result = self.runner(argv, self.timeout_seconds, self._sanitized_env())
        except subprocess.TimeoutExpired as exc:
            raise OpenClawClientError("cli_timeout", code="timeout") from exc
        payload: Dict[str, Any] = {
            "available": result.returncode == 0,
            "returncode": result.returncode,
            "argv": list(argv),
            "stdout": (result.stdout or "")[:4000],
            "stderr": (result.stderr or "")[:2000],
            "rpc_required": True,
            "evidence_class": LIVE_READ_ONLY if result.returncode == 0 else ERROR,
        }
        # Attempt JSON parse if CLI emitted JSON despite no --json flag.
        text = (result.stdout or "").strip()
        if text.startswith("{"):
            try:
                payload["parsed"] = json.loads(text)
            except json.JSONDecodeError:
                payload["parse_error"] = "invalid_json"
        if result.returncode != 0:
            payload["error"] = {
                "code": "gateway_unavailable",
                "returncode": result.returncode,
            }
        return payload

    def _run_json(self, argv: Sequence[str], *, label: str) -> Dict[str, Any]:
        assert self.runner is not None
        try:
            result = self.runner(argv, self.timeout_seconds, self._sanitized_env())
        except subprocess.TimeoutExpired as exc:
            raise OpenClawClientError("cli_timeout", code="timeout") from exc
        if result.returncode != 0:
            return {
                "available": False,
                "evidence_class": ERROR,
                "error": {
                    "code": f"{label}_failed",
                    "returncode": result.returncode,
                    "stderr": (result.stderr or "")[:2000],
                },
                "argv": list(argv),
            }
        try:
            parsed = json.loads(result.stdout or "")
        except json.JSONDecodeError:
            return {
                "available": False,
                "evidence_class": ERROR,
                "error": {"code": "invalid_status_json"},
                "argv": list(argv),
                "stdout_preview": (result.stdout or "")[:500],
            }
        if not isinstance(parsed, dict):
            return {
                "available": False,
                "evidence_class": ERROR,
                "error": {"code": "unexpected_status_payload"},
                "argv": list(argv),
            }
        return {
            "available": True,
            "evidence_class": LIVE_READ_ONLY,
            "status": parsed,
            "argv": list(argv),
        }

"""OCI / process boundary abstractions for sandbox ACP execution."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence
import io
import json
import subprocess
import threading
import time

from engineering_os.infrastructure.acp.acp_fixture import AcpFixturePeer


class OciProcessError(RuntimeError):
    def __init__(self, message: str, *, code: str = "oci_process_error") -> None:
        super().__init__(message)
        self.code = code


# Termination reasons persisted independently of ACP protocol status.
TERMINATION_STDIN_CLOSED = "stdin_closed"
TERMINATION_SIGTERM = "sigterm"
TERMINATION_SIGKILL = "sigkill"
TERMINATION_EXITED = "exited"
TERMINATION_TIMEOUT = "timeout"
TERMINATION_CANCELLED = "cancelled"
TERMINATION_ALREADY_DEAD = "already_dead"


@dataclass
class OciProcessResult:
    returncode: int
    stdout: str
    stderr: str
    container_id: Optional[str] = None
    timed_out: bool = False
    cancelled: bool = False
    cleaned_up: bool = False
    process_exited_cleanly: bool = False
    termination_reason: Optional[str] = None
    cleanup_verified: bool = False
    sigkill_used: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "returncode": self.returncode,
            "stdout_bytes": len(self.stdout.encode("utf-8")),
            "stderr_bytes": len(self.stderr.encode("utf-8")),
            "stderr_preview": self.stderr[:500],
            "container_id": self.container_id,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "cleaned_up": self.cleaned_up,
            "process_exited_cleanly": self.process_exited_cleanly,
            "termination_reason": self.termination_reason,
            "cleanup_verified": self.cleanup_verified,
            "sigkill_used": self.sigkill_used,
        }


def classify_exit(returncode: Optional[int]) -> Dict[str, Any]:
    """Normalize Linux negative signals (-9) and shell-style 128+N (137)."""
    if returncode is None:
        return {
            "exit_code": None,
            "signal": None,
            "process_exited_cleanly": False,
            "killed_by_sigkill": False,
        }
    signal = None
    killed = False
    if returncode < 0:
        signal = -returncode
        killed = signal == 9
    elif returncode >= 128:
        signal = returncode - 128
        killed = signal == 9
    clean = returncode == 0
    return {
        "exit_code": returncode,
        "signal": signal,
        "process_exited_cleanly": clean,
        "killed_by_sigkill": killed,
    }


class OciProcessHandle(ABC):
    """Bidirectional stdio handle to a containerized (or injected) process."""

    @abstractmethod
    def write_line(self, line: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def read_line(self, timeout: float) -> Optional[str]:
        raise NotImplementedError

    @abstractmethod
    def poll_exit(self) -> Optional[int]:
        raise NotImplementedError

    @abstractmethod
    def close_stdin(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def terminate(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def kill(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def wait(self, timeout: Optional[float] = None) -> OciProcessResult:
        raise NotImplementedError

    @abstractmethod
    def shutdown_gracefully(self, *, grace_seconds: float = 2.0) -> OciProcessResult:
        """EOF/stdin close → SIGTERM → wait(grace) → SIGKILL only if needed."""
        raise NotImplementedError

    @abstractmethod
    def cleanup(self, *, grace_seconds: float = 2.0) -> Dict[str, Any]:
        raise NotImplementedError

    @property
    @abstractmethod
    def container_id(self) -> Optional[str]:
        raise NotImplementedError

    @property
    def stderr_text(self) -> str:
        return ""

    @property
    def last_termination_reason(self) -> Optional[str]:
        return None


class InjectedFixtureProcess(OciProcessHandle):
    """In-process ACP fixture that speaks NDJSON — used for offline tests/demo."""

    def __init__(
        self,
        *,
        scenario: str = "success",
        container_id: str = "injected-ctr",
        sticky_alive: bool = False,
        ignore_terminate: bool = False,
    ) -> None:
        self.peer = AcpFixturePeer()
        self.scenario = scenario
        self._container_id = container_id
        self._stdout: List[str] = []
        self._stderr = io.StringIO()
        self._alive = True
        self._returncode: Optional[int] = None
        self._lock = threading.Lock()
        self._cancelled = False
        self._timed_out = False
        self._cleaned = False
        self._sticky_alive = sticky_alive
        self._ignore_terminate = ignore_terminate
        self._termination_reason: Optional[str] = None
        self._sigkill_used = False
        self._stdin_closed = False
        self._cleanup_verified = False
        if scenario == "crash_on_start":
            self._alive = False
            self._returncode = 137
            self._termination_reason = TERMINATION_SIGKILL
            self._sigkill_used = True
            self._stderr.write("fixture_crashed\n")

    @property
    def container_id(self) -> Optional[str]:
        return self._container_id

    @property
    def stderr_text(self) -> str:
        return self._stderr.getvalue()

    @property
    def last_termination_reason(self) -> Optional[str]:
        return self._termination_reason

    def write_line(self, line: str) -> None:
        with self._lock:
            if not self._alive:
                raise OciProcessError("process_not_alive", code="dead")
            if self._stdin_closed:
                raise OciProcessError("stdin_closed", code="stdin")
            if self.scenario == "timeout":
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    return
                if msg.get("method") == "session/prompt":
                    self._stderr.write("holding_for_timeout\n")
                    return
            if self.scenario == "bad_json_response":
                self._stdout.append("{not-json")
                return
            try:
                outs = self.peer.handle_line(line)
            except Exception as exc:  # noqa: BLE001
                self._stderr.write(f"fixture_error:{exc}\n")
                self._alive = False
                self._returncode = 1
                self._termination_reason = TERMINATION_EXITED
                return
            self._stdout.extend(outs)
            if self.peer.cancelled:
                self._alive = False
                self._returncode = 0
                self._cancelled = True
                self._termination_reason = TERMINATION_CANCELLED

    def read_line(self, timeout: float) -> Optional[str]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if self._stdout:
                    return self._stdout.pop(0)
                if not self._alive and not self._stdout:
                    return None
            time.sleep(0.01)
        return None

    def poll_exit(self) -> Optional[int]:
        return self._returncode

    def close_stdin(self) -> None:
        with self._lock:
            self._stdin_closed = True
            if self._sticky_alive:
                return
            if self._alive and self._returncode is None:
                self._alive = False
                self._returncode = 0
                self._termination_reason = TERMINATION_STDIN_CLOSED

    def terminate(self) -> None:
        with self._lock:
            self._cancelled = True
            if self._ignore_terminate or self._sticky_alive:
                return
            self._alive = False
            if self._returncode is None:
                self._returncode = 0
                self._termination_reason = TERMINATION_SIGTERM

    def kill(self) -> None:
        with self._lock:
            self._alive = False
            self._sigkill_used = True
            if self._returncode is None:
                # Mirror real Linux SIGKILL attribution for regression coverage.
                self._returncode = -9
                self._termination_reason = TERMINATION_SIGKILL

    def wait(self, timeout: Optional[float] = None) -> OciProcessResult:
        if timeout is not None and self.scenario == "timeout" and self._alive:
            time.sleep(min(timeout, 0.05))
            self._timed_out = True
            self.kill()
        deadline = None if timeout is None else time.time() + timeout
        while self._alive and self._returncode is None:
            if deadline is not None and time.time() >= deadline:
                break
            time.sleep(0.01)
        classified = classify_exit(self._returncode)
        return OciProcessResult(
            returncode=self._returncode if self._returncode is not None else -1,
            stdout="",
            stderr=self.stderr_text,
            container_id=self._container_id,
            timed_out=self._timed_out,
            cancelled=self._cancelled,
            cleaned_up=self._cleaned,
            process_exited_cleanly=bool(classified["process_exited_cleanly"]),
            termination_reason=self._termination_reason,
            cleanup_verified=self._cleanup_verified,
            sigkill_used=self._sigkill_used,
        )

    def shutdown_gracefully(self, *, grace_seconds: float = 2.0) -> OciProcessResult:
        if self.poll_exit() is not None:
            self._termination_reason = self._termination_reason or TERMINATION_ALREADY_DEAD
            return self.wait(timeout=0.01)
        self.close_stdin()
        if self.poll_exit() is not None:
            return self.wait(timeout=0.01)
        self.terminate()
        # Honor grace window for sticky/ignore-terminate fixtures.
        deadline = time.time() + max(0.0, grace_seconds)
        while self.poll_exit() is None and time.time() < deadline:
            time.sleep(0.01)
        if self.poll_exit() is None:
            self.kill()
        return self.wait(timeout=0.05)

    def cleanup(self, *, grace_seconds: float = 2.0) -> Dict[str, Any]:
        result = self.shutdown_gracefully(grace_seconds=grace_seconds)
        self._cleaned = True
        self._cleanup_verified = True
        self._alive = False
        return {
            "cleaned_up": True,
            "cleanup_verified": True,
            "container_id": self._container_id,
            "mode": "injected",
            "exit_code": result.returncode,
            "process_exited_cleanly": result.process_exited_cleanly,
            "termination_reason": result.termination_reason,
            "sigkill_used": result.sigkill_used,
        }


class SubprocessOciHandle(OciProcessHandle):
    """Wraps a real subprocess.Popen (Podman or local)."""

    def __init__(
        self,
        proc: subprocess.Popen[str],
        *,
        container_name: str,
        container_id: Optional[str] = None,
        cleanup_argv: Optional[Sequence[str]] = None,
        runner: Optional[Any] = None,
        grace_seconds: float = 2.0,
    ) -> None:
        self.proc = proc
        self.container_name = container_name
        self._container_id = container_id or container_name
        self.cleanup_argv = list(cleanup_argv or [])
        self.runner = runner
        self.grace_seconds = grace_seconds
        self._stderr_buf = io.StringIO()
        self._stdout_queue: List[str] = []
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._err_reader = threading.Thread(target=self._read_stderr, daemon=True)
        self._reader.start()
        self._err_reader.start()
        self._cleaned = False
        self._cancelled = False
        self._timed_out = False
        self._termination_reason: Optional[str] = None
        self._sigkill_used = False
        self._cleanup_verified = False
        self._stdin_closed = False

    @property
    def container_id(self) -> Optional[str]:
        return self._container_id

    @property
    def stderr_text(self) -> str:
        return self._stderr_buf.getvalue()

    @property
    def last_termination_reason(self) -> Optional[str]:
        return self._termination_reason

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            with self._lock:
                self._stdout_queue.append(line.rstrip("\n"))

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self._stderr_buf.write(line)

    def write_line(self, line: str) -> None:
        if self.proc.stdin is None or self._stdin_closed:
            raise OciProcessError("stdin_closed", code="stdin")
        self.proc.stdin.write(line if line.endswith("\n") else line + "\n")
        self.proc.stdin.flush()

    def read_line(self, timeout: float) -> Optional[str]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if self._stdout_queue:
                    return self._stdout_queue.pop(0)
            if self.proc.poll() is not None:
                with self._lock:
                    if self._stdout_queue:
                        return self._stdout_queue.pop(0)
                return None
            time.sleep(0.01)
        return None

    def poll_exit(self) -> Optional[int]:
        return self.proc.poll()

    def close_stdin(self) -> None:
        if self._stdin_closed:
            return
        self._stdin_closed = True
        if self.proc.stdin is not None and not self.proc.stdin.closed:
            try:
                self.proc.stdin.close()
            except Exception:
                pass

    def terminate(self) -> None:
        self._cancelled = True
        if self.proc.poll() is None:
            self.proc.terminate()
            if self._termination_reason is None:
                self._termination_reason = TERMINATION_SIGTERM

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self._sigkill_used = True
            self._termination_reason = TERMINATION_SIGKILL

    def wait(self, timeout: Optional[float] = None) -> OciProcessResult:
        try:
            code = self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._timed_out = True
            self.kill()
            code = self.proc.wait(timeout=5)
            self._termination_reason = TERMINATION_TIMEOUT
        classified = classify_exit(code)
        if self._termination_reason is None and classified["process_exited_cleanly"]:
            self._termination_reason = (
                TERMINATION_STDIN_CLOSED if self._stdin_closed else TERMINATION_EXITED
            )
        elif self._termination_reason is None and classified["killed_by_sigkill"]:
            self._termination_reason = TERMINATION_SIGKILL
            self._sigkill_used = True
        return OciProcessResult(
            returncode=code if code is not None else -1,
            stdout="",
            stderr=self.stderr_text,
            container_id=self._container_id,
            timed_out=self._timed_out,
            cancelled=self._cancelled,
            cleaned_up=self._cleaned,
            process_exited_cleanly=bool(classified["process_exited_cleanly"]),
            termination_reason=self._termination_reason,
            cleanup_verified=self._cleanup_verified,
            sigkill_used=self._sigkill_used,
        )

    def shutdown_gracefully(self, *, grace_seconds: float = 2.0) -> OciProcessResult:
        if self.proc.poll() is not None:
            self._termination_reason = self._termination_reason or TERMINATION_ALREADY_DEAD
            return self.wait(timeout=0.1)
        # 1) Close stdin (EOF) so ACP peers that exit on EOF can finish cleanly.
        self.close_stdin()
        try:
            code = self.proc.wait(timeout=min(grace_seconds, 1.0))
            self._termination_reason = TERMINATION_STDIN_CLOSED
            classified = classify_exit(code)
            return OciProcessResult(
                returncode=code if code is not None else -1,
                stdout="",
                stderr=self.stderr_text,
                container_id=self._container_id,
                timed_out=False,
                cancelled=self._cancelled,
                cleaned_up=self._cleaned,
                process_exited_cleanly=bool(classified["process_exited_cleanly"]),
                termination_reason=self._termination_reason,
                cleanup_verified=self._cleanup_verified,
                sigkill_used=False,
            )
        except subprocess.TimeoutExpired:
            pass
        # 2) SIGTERM
        self.terminate()
        try:
            code = self.proc.wait(timeout=grace_seconds)
            classified = classify_exit(code)
            return OciProcessResult(
                returncode=code if code is not None else -1,
                stdout="",
                stderr=self.stderr_text,
                container_id=self._container_id,
                timed_out=False,
                cancelled=self._cancelled,
                cleaned_up=self._cleaned,
                process_exited_cleanly=bool(classified["process_exited_cleanly"]),
                termination_reason=self._termination_reason or TERMINATION_SIGTERM,
                cleanup_verified=self._cleanup_verified,
                sigkill_used=False,
            )
        except subprocess.TimeoutExpired:
            pass
        # 3) SIGKILL fallback only
        self.kill()
        return self.wait(timeout=5)

    def cleanup(self, *, grace_seconds: float = 2.0) -> Dict[str, Any]:
        grace = grace_seconds if grace_seconds is not None else self.grace_seconds
        result = self.shutdown_gracefully(grace_seconds=grace)
        cleanup_rc = None
        cleanup_error = None
        if self.cleanup_argv:
            try:
                if self.runner:
                    completed = self.runner(self.cleanup_argv, 10.0)
                    cleanup_rc = getattr(completed, "returncode", None)
                else:
                    completed = subprocess.run(
                        list(self.cleanup_argv),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    cleanup_rc = completed.returncode
            except Exception as exc:  # noqa: BLE001
                cleanup_error = str(exc)
                self._cleaned = False
                self._cleanup_verified = False
                return {
                    "cleaned_up": False,
                    "cleanup_verified": False,
                    "error": cleanup_error,
                    "container_id": self._container_id,
                    "exit_code": result.returncode,
                    "process_exited_cleanly": result.process_exited_cleanly,
                    "termination_reason": result.termination_reason,
                    "sigkill_used": result.sigkill_used,
                }
        self._cleaned = True
        self._cleanup_verified = cleanup_error is None and (
            cleanup_rc in (0, None) or True
        )
        # Cleanup verified when container remove succeeded or no remove needed.
        if cleanup_rc not in (0, None) and self.cleanup_argv:
            self._cleanup_verified = False
        else:
            self._cleanup_verified = True
        return {
            "cleaned_up": True,
            "cleanup_verified": self._cleanup_verified,
            "cleanup_returncode": cleanup_rc,
            "container_id": self._container_id,
            "exit_code": result.returncode,
            "process_exited_cleanly": result.process_exited_cleanly,
            "termination_reason": result.termination_reason,
            "sigkill_used": result.sigkill_used,
        }

"""OCI / process boundary abstractions for sandbox ACP execution."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence
import io
import json
import subprocess
import threading
import time

from engineering_os.infrastructure.acp_fixture import AcpFixturePeer


class OciProcessError(RuntimeError):
    def __init__(self, message: str, *, code: str = "oci_process_error") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class OciProcessResult:
    returncode: int
    stdout: str
    stderr: str
    container_id: Optional[str] = None
    timed_out: bool = False
    cancelled: bool = False
    cleaned_up: bool = False

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
    def terminate(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def kill(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def wait(self, timeout: Optional[float] = None) -> OciProcessResult:
        raise NotImplementedError

    @abstractmethod
    def cleanup(self) -> Dict[str, Any]:
        raise NotImplementedError

    @property
    @abstractmethod
    def container_id(self) -> Optional[str]:
        raise NotImplementedError

    @property
    def stderr_text(self) -> str:
        return ""


class InjectedFixtureProcess(OciProcessHandle):
    """In-process ACP fixture that speaks NDJSON — used for offline tests/demo."""

    def __init__(self, *, scenario: str = "success", container_id: str = "injected-ctr") -> None:
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
        if scenario == "crash_on_start":
            self._alive = False
            self._returncode = 137
            self._stderr.write("fixture_crashed\n")

    @property
    def container_id(self) -> Optional[str]:
        return self._container_id

    @property
    def stderr_text(self) -> str:
        return self._stderr.getvalue()

    def write_line(self, line: str) -> None:
        with self._lock:
            if not self._alive:
                raise OciProcessError("process_not_alive", code="dead")
            if self.scenario == "timeout":
                # Do not produce a prompt response; caller times out.
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
                return
            self._stdout.extend(outs)
            if self.peer.cancelled:
                self._alive = False
                self._returncode = 0
                self._cancelled = True

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

    def terminate(self) -> None:
        with self._lock:
            self._alive = False
            self._cancelled = True
            if self._returncode is None:
                self._returncode = 0

    def kill(self) -> None:
        with self._lock:
            self._alive = False
            if self._returncode is None:
                self._returncode = 137

    def wait(self, timeout: Optional[float] = None) -> OciProcessResult:
        if timeout is not None and self.scenario == "timeout" and self._alive:
            time.sleep(min(timeout, 0.05))
            self._timed_out = True
            self.kill()
        while self._alive and self._returncode is None:
            time.sleep(0.01)
            if timeout is not None:
                break
        return OciProcessResult(
            returncode=self._returncode if self._returncode is not None else -1,
            stdout="",
            stderr=self.stderr_text,
            container_id=self._container_id,
            timed_out=self._timed_out,
            cancelled=self._cancelled,
            cleaned_up=self._cleaned,
        )

    def cleanup(self) -> Dict[str, Any]:
        self._cleaned = True
        self._alive = False
        return {"cleaned_up": True, "container_id": self._container_id, "mode": "injected"}


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
    ) -> None:
        self.proc = proc
        self.container_name = container_name
        self._container_id = container_id or container_name
        self.cleanup_argv = list(cleanup_argv or [])
        self.runner = runner
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

    @property
    def container_id(self) -> Optional[str]:
        return self._container_id

    @property
    def stderr_text(self) -> str:
        return self._stderr_buf.getvalue()

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
        if self.proc.stdin is None:
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

    def terminate(self) -> None:
        self._cancelled = True
        self.proc.terminate()

    def kill(self) -> None:
        self.proc.kill()

    def wait(self, timeout: Optional[float] = None) -> OciProcessResult:
        try:
            code = self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._timed_out = True
            self.kill()
            code = self.proc.wait(timeout=5)
        return OciProcessResult(
            returncode=code if code is not None else -1,
            stdout="",
            stderr=self.stderr_text,
            container_id=self._container_id,
            timed_out=self._timed_out,
            cancelled=self._cancelled,
            cleaned_up=self._cleaned,
        )

    def cleanup(self) -> Dict[str, Any]:
        if self.proc.poll() is None:
            self.kill()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        cleanup_rc = None
        if self.cleanup_argv:
            try:
                if self.runner:
                    result = self.runner(self.cleanup_argv, 10.0)
                    cleanup_rc = getattr(result, "returncode", None)
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
                return {
                    "cleaned_up": False,
                    "error": str(exc),
                    "container_id": self._container_id,
                }
        self._cleaned = True
        return {
            "cleaned_up": True,
            "cleanup_returncode": cleanup_rc,
            "container_id": self._container_id,
        }

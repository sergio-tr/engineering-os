"""Durable ACP session manager and evidence collector."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import uuid

from engineering_os.domain.models import new_id, utc_now
from engineering_os.infrastructure.acp.protocol.acp_protocol import (
    AcpProtocolError,
    initialize_params,
    make_request,
    make_response,
    parse_message,
)
from engineering_os.infrastructure.acp.protocol.acp_states import assert_acp_transition
from engineering_os.infrastructure.acp.transports.acp_transport import (
    AcpPermissionPolicy,
    AcpTransport,
    AcpTransportError,
)
from engineering_os.infrastructure.evidence import SYNTHETIC
from engineering_os.infrastructure.persistence.sqlite import Repository


class AcpEvidenceCollector:
    def __init__(self) -> None:
        self.refs: List[str] = []
        self.chunks: List[str] = []

    def note_chunk(self, text: str) -> None:
        if text:
            self.chunks.append(text)

    def note_evidence(self, refs: List[str]) -> None:
        self.refs.extend(refs)

    def finalize(self, session_id: str) -> List[str]:
        out = list(self.refs)
        if self.chunks:
            out.append(f"acp-transcript:{session_id}:{len(self.chunks)}")
        return out


class AcpSessionManager:
    """Owns ACP protocol lifecycle for one execution, with durable persistence."""

    def __init__(
        self,
        repo: Repository,
        transport: AcpTransport,
        *,
        permission_policy: Optional[AcpPermissionPolicy] = None,
        sandbox_gate: str = "NOT_TESTED",
    ) -> None:
        self.repo = repo
        self.transport = transport
        self.permission_policy = permission_policy or AcpPermissionPolicy()
        self.sandbox_gate = sandbox_gate
        self.pending: Dict[Any, str] = {}
        self.seen_event_keys: set[str] = set()
        self.evidence = AcpEvidenceCollector()

    def create_session_record(
        self,
        *,
        execution_id: str,
        project_id: str,
        task_id: str,
        agent_id: str = "cursor",
        backend: str = "synthetic-acp",
        transport_type: str = "in-memory-synthetic",
        protocol_version: int = 1,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        # Idempotent: one active session per execution.
        existing = self.repo.get_acp_session_by_execution(execution_id)
        if existing and existing["status"] not in {
            "COMPLETED",
            "FAILED",
            "CANCELLED",
            "TIMED_OUT",
        }:
            return existing
        record = {
            "session_id": new_id("acpsess"),
            "execution_id": execution_id,
            "project_id": project_id,
            "task_id": task_id,
            "agent_id": agent_id,
            "acp_backend": backend,
            "transport_type": transport_type,
            "protocol_version": protocol_version,
            "status": "CREATED",
            "correlation_id": correlation_id or new_id("corr"),
            "last_event_sequence": 0,
            "cancellation_state": None,
            "failure_reason": None,
            "evidence_refs": [],
            "runtime_provenance": self.transport.availability().to_dict(),
            "created_at": utc_now(),
            "started_at": None,
            "completed_at": None,
            "last_activity_at": utc_now(),
        }
        return self.repo.insert_acp_session(record)

    def _transition(self, session: Dict[str, Any], target: str, **fields: Any) -> Dict[str, Any]:
        assert_acp_transition(session["status"], target)
        session = dict(session)
        session["status"] = target
        session["last_activity_at"] = utc_now()
        for k, v in fields.items():
            session[k] = v
        return self.repo.update_acp_session(session)

    def _emit(
        self,
        session: Dict[str, Any],
        event_type: str,
        payload: Dict[str, Any],
        *,
        dedupe_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        key = dedupe_key or f"{session['session_id']}:{event_type}:{payload}"
        if key in self.seen_event_keys:
            return None
        # Also check durable duplicate markers.
        if dedupe_key and self.repo.acp_event_exists(session["session_id"], dedupe_key):
            return None
        self.seen_event_keys.add(key)
        seq = int(session.get("last_event_sequence") or 0) + 1
        event = self.repo.append_acp_event(
            {
                "event_id": new_id("acpevt"),
                "session_id": session["session_id"],
                "execution_id": session["execution_id"],
                "sequence": seq,
                "event_type": event_type,
                "dedupe_key": dedupe_key or key,
                "payload": payload,
                "timestamp": utc_now(),
            }
        )
        session["last_event_sequence"] = seq
        session["last_activity_at"] = utc_now()
        self.repo.update_acp_session(session)
        return event

    def run_to_completion(
        self,
        session: Dict[str, Any],
        *,
        prompt_text: str,
        mode: str = "SYNTHETIC",
    ) -> Dict[str, Any]:
        avail = self.transport.availability()
        if not avail.available and mode != "SYNTHETIC":
            session = self._transition(
                session, "FAILED", failure_reason="transport_unavailable"
            )
            self._emit(session, "acp.failed", {"reason": "transport_unavailable"})
            return session

        session = self._transition(session, "INITIALIZING", started_at=utc_now())
        self._emit(session, "acp.initializing", {"backend": avail.backend})

        try:
            init = self.transport.send(
                make_request("initialize", initialize_params())
            )
            if not init or "error" in init:
                raise AcpTransportError(
                    (init or {}).get("error", {}).get("message", "initialize_failed"),
                    code="initialize_failed",
                )
            negotiated = (init.get("result") or {}).get("protocolVersion")
            if negotiated not in {1, session.get("protocol_version")}:
                raise AcpProtocolError("protocol_negotiation_failed")
            session["protocol_version"] = negotiated
            self.repo.update_acp_session(session)
            self._drain(session)

            auth = self.transport.send(
                make_request("authenticate", {"methodId": "cursor_login"})
            )
            if auth and "error" in auth:
                raise AcpTransportError("authenticate_failed", code="authenticate_failed")
            self._drain(session)

            created = self.transport.send(
                make_request("session/new", {"cwd": "/tmp/eos-synthetic", "mcpServers": []})
            )
            if not created or "error" in created:
                raise AcpTransportError("session_create_failed", code="session_fail")
            remote_session = (created.get("result") or {}).get("sessionId")
            session["runtime_provenance"] = {
                **(session.get("runtime_provenance") or {}),
                "remote_session_id": remote_session,
                "mode": mode,
            }
            session = self._transition(session, "READY")
            self._emit(
                session,
                "acp.session_ready",
                {"remote_session_id": remote_session},
                dedupe_key=f"{session['session_id']}:ready:{remote_session}",
            )

            session = self._transition(session, "RUNNING")
            self._emit(session, "acp.prompt_submitted", {"prompt_chars": len(prompt_text)})
            prompt_resp = self.transport.send(
                make_request(
                    "session/prompt",
                    {
                        "sessionId": remote_session,
                        "prompt": [{"type": "text", "text": prompt_text}],
                    },
                )
            )
            self._drain(session)

            # Handle permission requests that arrived before/without prompt response.
            self._handle_permissions(session)

            if prompt_resp is None and mode == "SYNTHETIC":
                # Some scenarios (permission/timeout) defer completion.
                self._drain(session)
                self._handle_permissions(session)
                scenario = getattr(self.transport, "scenario", None)
                peer = getattr(self.transport, "peer", None)
                if scenario is None and peer is not None:
                    scenario = getattr(peer, "scenario", None)
                if session["status"] == "RUNNING":
                    if scenario == "timeout":
                        session = self._transition(
                            session, "TIMED_OUT", failure_reason="acp_timeout"
                        )
                        self._emit(session, "acp.timed_out", {})
                        return session
                    if scenario == "permission_denied":
                        session = self._transition(
                            session,
                            "BLOCKED",
                            failure_reason="permission_denied_by_policy",
                        )
                        self._emit(session, "acp.permission_denied", {})
                        session = self._transition(
                            session, "FAILED", failure_reason="permission_denied_by_policy"
                        )
                        self._emit(session, "acp.failed", {"reason": "permission_denied"})
                        return session

            if prompt_resp and "error" in prompt_resp:
                reason = prompt_resp["error"].get("message", "prompt_failed")
                if "interrupted" in reason:
                    session = self._transition(
                        session, "INTERRUPTED", failure_reason=reason
                    )
                    self._emit(session, "acp.interrupted", {"reason": reason})
                    session = self._transition(session, "FAILED", failure_reason=reason)
                else:
                    session = self._transition(session, "FAILED", failure_reason=reason)
                self._emit(session, "acp.failed", {"reason": reason})
                return session

            result = (prompt_resp or {}).get("result") or {}
            refs = list(result.get("evidence") or [])
            self.evidence.note_evidence(refs)
            final_refs = self.evidence.finalize(session["session_id"])
            session = self._transition(
                session,
                "COMPLETED",
                completed_at=utc_now(),
                evidence_refs=final_refs,
            )
            self._emit(
                session,
                "acp.completed",
                {
                    "stopReason": result.get("stopReason"),
                    "evidence": final_refs,
                    "mode": mode,
                },
                dedupe_key=f"{session['session_id']}:completed",
            )
            # Duplicate completion is ignored
            self._emit(
                session,
                "acp.completed",
                {"stopReason": result.get("stopReason")},
                dedupe_key=f"{session['session_id']}:completed",
            )
            return session
        except (AcpTransportError, AcpProtocolError) as exc:
            if session["status"] in {"CREATED"}:
                session = self._transition(session, "INITIALIZING")
            if session["status"] in {"INITIALIZING"}:
                session = self._transition(
                    session, "FAILED", failure_reason=str(exc)
                )
            elif session["status"] in {"READY", "RUNNING", "BLOCKED", "INTERRUPTED"}:
                if session["status"] == "READY":
                    session = self._transition(session, "FAILED", failure_reason=str(exc))
                elif session["status"] == "RUNNING":
                    session = self._transition(session, "FAILED", failure_reason=str(exc))
                elif session["status"] == "INTERRUPTED":
                    session = self._transition(session, "FAILED", failure_reason=str(exc))
                else:
                    session = self._transition(session, "FAILED", failure_reason=str(exc))
            self._emit(session, "acp.failed", {"reason": str(exc), "code": getattr(exc, "code", None)})
            return session
        finally:
            try:
                self.transport.close()
            except Exception:
                pass

    def cancel(self, session: Dict[str, Any], *, synthetic: bool = True) -> Dict[str, Any]:
        if session["status"] in {"COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"}:
            return session
        if session["status"] not in {"CANCEL_REQUESTED"}:
            if session["status"] in {"RUNNING", "INITIALIZING", "READY", "BLOCKED"}:
                session = self._transition(session, "CANCEL_REQUESTED", cancellation_state="requested")
                self._emit(session, "acp.cancel_requested", {"synthetic": synthetic})
        remote = (session.get("runtime_provenance") or {}).get("remote_session_id")
        try:
            self.transport.send(
                make_request("session/cancel", {"sessionId": remote})
            )
        except AcpTransportError:
            pass
        session = self._transition(
            session, "CANCELLED", cancellation_state="cancelled", completed_at=utc_now()
        )
        self._emit(session, "acp.cancelled", {})
        return session

    def _handle_permissions(self, session: Dict[str, Any]) -> None:
        for raw in list(self.transport.poll()):
            self._consume_message(session, raw)
        # Also process any permission requests still needing answers via send path
        # (InMemory queues them as requests in poll).

    def _drain(self, session: Dict[str, Any]) -> None:
        for raw in self.transport.poll():
            self._consume_message(session, raw)

    def _consume_message(self, session: Dict[str, Any], raw: Dict[str, Any]) -> None:
        msg = parse_message(raw)
        if msg.is_notification and raw.get("method") == "session/update":
            update = (raw.get("params") or {}).get("update") or {}
            text = ""
            content = update.get("content") or {}
            if isinstance(content, dict):
                text = str(content.get("text") or "")
            self.evidence.note_chunk(text)
            dedupe = f"{session['session_id']}:upd:{update.get('sessionUpdate')}:{text[:40]}"
            self._emit(
                session,
                "acp.session_update",
                {"update": update},
                dedupe_key=dedupe,
            )
            return
        if msg.is_request and raw.get("method") == "session/request_permission":
            decision = self.permission_policy.decide(raw.get("params") or {})
            self._emit(
                session,
                "acp.permission_request",
                {"params": raw.get("params"), "decision": decision},
                dedupe_key=f"{session['session_id']}:perm:{raw.get('id')}",
            )
            # Reply deny — never auto-approve.
            self.transport.send(make_response(raw.get("id"), decision))
            return
        if msg.is_response:
            # Uncorrelated responses are ignored after validation.
            return
        # Unknown methods from peer
        if msg.is_request or msg.is_notification:
            self._emit(
                session,
                "acp.unknown_method",
                {"method": raw.get("method")},
                dedupe_key=f"{session['session_id']}:unk:{raw.get('method')}:{raw.get('id')}",
            )

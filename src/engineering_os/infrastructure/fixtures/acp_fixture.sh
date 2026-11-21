#!/bin/sh
# Engineering OS ACP fixture agent (EOS-08).
# Runs on Alpine/BusyBox. Speaks a fixed NDJSON ACP subset over stdin/stdout.
# Supported methods: initialize, authenticate, session/new, session/prompt, session/cancel.
# Not a general Cursor ACP agent. No network. No shell evaluation of message bodies.
set -eu

SESSION_ID=""
INITIALIZED=0

emit() {
  printf '%s\n' "$1"
}

extract_id() {
  # Best-effort numeric/string id extraction for fixture responses.
  printf '%s' "$1" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\?\([A-Za-z0-9_-]*\)"\?.*/\1/p' | head -n 1
}

while IFS= read -r line || [ -n "$line" ]; do
  [ -z "$line" ] && continue
  case "$line" in
    *'"method":"initialize"'*|*'\"method\":\"initialize\"'*)
      rid=$(extract_id "$line")
      INITIALIZED=1
      emit "{\"jsonrpc\":\"2.0\",\"id\":${rid:-1},\"result\":{\"protocolVersion\":1,\"agentCapabilities\":{\"loadSession\":true},\"agentInfo\":{\"name\":\"eos-acp-fixture\",\"version\":\"eos08\"}}}"
      ;;
    *'"method":"authenticate"'*|*'\"method\":\"authenticate\"'*)
      rid=$(extract_id "$line")
      if [ "$INITIALIZED" -ne 1 ]; then
        emit "{\"jsonrpc\":\"2.0\",\"id\":${rid:-1},\"error\":{\"code\":-32001,\"message\":\"not_initialized\"}}"
      else
        emit "{\"jsonrpc\":\"2.0\",\"id\":${rid:-1},\"result\":{\"ok\":true}}"
      fi
      ;;
    *'"method":"session/new"'*|*'\"method\":\"session/new\"'*)
      rid=$(extract_id "$line")
      SESSION_ID="fix-sess-$$"
      emit "{\"jsonrpc\":\"2.0\",\"id\":${rid:-1},\"result\":{\"sessionId\":\"${SESSION_ID}\"}}"
      ;;
    *'"method":"session/prompt"'*|*'\"method\":\"session/prompt\"'*)
      rid=$(extract_id "$line")
      emit "{\"jsonrpc\":\"2.0\",\"method\":\"session/update\",\"params\":{\"sessionId\":\"${SESSION_ID}\",\"update\":{\"sessionUpdate\":\"agent_message_chunk\",\"content\":{\"text\":\"fixture working\"}}}}"
      emit "{\"jsonrpc\":\"2.0\",\"id\":${rid:-1},\"result\":{\"stopReason\":\"end_turn\",\"evidence\":[\"oci-fixture-${SESSION_ID}\"],\"completedAt\":\"fixture\"}}"
      ;;
    *'"method":"session/cancel"'*|*'\"method\":\"session/cancel\"'*)
      rid=$(extract_id "$line")
      emit "{\"jsonrpc\":\"2.0\",\"id\":${rid:-1},\"result\":{\"cancelled\":true}}"
      exit 0
      ;;
    *)
      rid=$(extract_id "$line")
      emit "{\"jsonrpc\":\"2.0\",\"id\":${rid:-0},\"error\":{\"code\":-32601,\"message\":\"method_not_found_fixture\"}}"
      ;;
  esac
done

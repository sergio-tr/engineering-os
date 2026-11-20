# M01-00 validation — Cursor CLI ACP discovery

**Explicit statement:** No live ACP session occurred during this discovery.

## Environment-neutral summary

| Item | Result |
|------|--------|
| `cursor-agent` on PATH | Observed present |
| Reported version | `2026.09.23-86fc751` |
| `acp` subcommand | Observed; help describes starting an ACP server |
| ACP-specific CLI flags in `acp --help` | Only `-h, --help` documented |
| Live ACP session | Not started (`NOT_TESTED`) |
| ACP gate | Remains `NOT_TESTED` |
| SANDBOX gate | Unchanged; still required before M01-01 |

## Commands executed and exit codes

| Command | Exit code | Notes |
|---------|-----------|-------|
| `command -v cursor-agent` | 0 | Binary/symlink resolved on PATH |
| `timeout 15s cursor-agent --version` | 0 | Version printed |
| `timeout 15s cursor-agent --help` | 0 | Top-level agent CLI help |
| `timeout 15s cursor-agent acp --help` | 0 | ACP subcommand help |

No authentication, resume, workspace-trust, network, install, or session-start commands were executed.

## Sanitized relevant CLI output

### Version

```text
2026.09.23-86fc751
```

### ACP help (complete observed text)

```text
Usage: agent acp [options]

Start the Cursor Agent as an ACP (Agent Client Protocol) server

Options:
  -h, --help  Display help for command
```

### Top-level help — selected observations (sanitized)

Observed from `cursor-agent --help` (usage line reports `agent`):

- Global authentication-related options documented: `--api-key`, `login`, `logout`, `status|whoami`.
- Workspace-related options documented: `--workspace`, `--add-dir`, `--trust`, worktree-related flags.
- Session-related options documented: `--resume`, `--continue`, `persist`, `ls`, `resume`.
- Execution-mode options documented: `--mode plan|ask`, `--plan`, `--print`, sandbox enable/disable flag on the general agent CLI.
- Default API endpoint text is documented by the CLI help; this discovery did **not** call that endpoint.
- The top-level `Commands:` list observed in this run did **not** enumerate `acp`, even though `cursor-agent acp --help` succeeded.

Absolute install paths and account identifiers are omitted from this report.

## Discovery criteria

| Criterion | Status | Evidence class |
|-----------|--------|----------------|
| `cursor-agent` available locally | **PASS** | Observed (`command -v`, version) |
| Version reported | **PASS** | Observed `2026.09.23-86fc751` |
| `acp` command exposed | **PASS** | Observed `cursor-agent acp --help` |
| ACP startup flags / documented options | **PASS** (documented surface only) | Only `-h/--help` on `acp`; no other ACP-specific flags observed |
| Transport and session lifecycle from local help | **NOT_TESTED** / unknown | ACP help does not document transport, stdio/WebSocket, or lifecycle |
| Authentication / workspace prerequisites documented on general CLI | **PASS** (documentation-derived) | General help lists auth and workspace options; not exercised |
| Authentication actually satisfied for ACP | **NOT_TESTED** | No login/status/session |
| Real ACP session start | **NOT_TESTED** | Prohibited in M01-00 |
| Protocol message exchange / tool calls | **NOT_TESTED** | Requires live session |
| Effective isolation via external sandbox | **NOT_TESTED** | SANDBOX gate pending; CLI `--sandbox` flag is not a substitute for EOS external sandbox |
| ACP gate closed | **NOT_TESTED** | Requires later evidenced session after SANDBOX |

## Observed ACP interface

**Observed facts:**

1. Invoking `cursor-agent acp --help` succeeds and identifies the mode as starting the Cursor Agent as an “ACP (Agent Client Protocol) server”.
2. The ACP subcommand help documents no startup flags beyond `--help`.
3. The installed CLI version string is `2026.09.23-86fc751`.

**Documentation-derived claims (general `agent` CLI, not proven for `acp`):**

1. Authentication may use API key, login flow, or related status commands.
2. Workspace selection and trust prompts exist on the general CLI.
3. Session resume/continue/persist commands exist on the general CLI.

**Inferences (non-authoritative):**

1. `acp` may be an under-documented or separately wired subcommand because it was not listed in the observed top-level Commands section.
2. General agent flags might or might not apply to `acp`; this was not tested.

**Unknowns:**

1. Transport binding (stdio, socket, or other).
2. How an ACP client authenticates a session.
3. How workspace roots are selected for ACP mode.
4. Which tools are exposed over ACP.
5. Whether parent CLI flags such as `--workspace`, `--api-key`, or `--sandbox` affect `acp`.

## Unverified runtime capabilities

- Starting and stopping an ACP server process.
- Client handshake and capability negotiation.
- Prompt/task submission and streaming responses.
- File/tool permissions under ACP.
- Interaction with Engineering OS `ExecutionContract` fields.
- Behavior inside an external sandbox.
- Cost, model selection, and account entitlements.

## Requirements for a future sandboxed ACP proof of concept

Before M01-01 (controlled ACP session):

1. **SANDBOX gate (`M03-02`) must PASS** with external isolation evidence. Prompts, cwd, and CLI `--sandbox` are not sufficient EOS enforcement.
2. Owner authorization for a narrowly scoped synthetic or disposable project.
3. Explicit allow-list of ACP client commands and success criteria.
4. No credentials printed into the public repository.
5. Capture of protocol-level evidence (sanitized) proving session start, bounded action, and clean shutdown.
6. Mapping of observed ACP behavior to Engineering OS contracts without claiming native schema compatibility.

## Classification reminder

| Class | Use in this document |
|-------|----------------------|
| Observed | Commands and help text captured in this run |
| Documentation-derived | General CLI help text not exercised against `acp` |
| Inferred | Marked as such; not used to claim PASS on runtime |
| Unknown / NOT_TESTED | Anything requiring a live session or private config |

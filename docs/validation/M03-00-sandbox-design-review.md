# M03-00 validation — Sandbox design review

**Explicit statements:**

- No sandbox runtime was created, started, or tested.
- No Cursor ACP session was started.
- No container or VM was launched.
- The SANDBOX gate remains **NOT_TESTED**.

## Inspection methods

| Method | Purpose |
|--------|---------|
| Git history on `main` | Verify M01-00 Owner integration and dependency readiness |
| Read of baseline, contracts, permission matrix, M01-00 evidence | Align design with existing EOS invariants |
| Optional non-mutating `command -v` / `--version` | Technology presence only; not adoption proof |

## Findings

### Dependency and merge evidence

| Item | Result |
|------|--------|
| Repository | `sergio-tr/engineering-os` |
| Branch for this work | `docs/m03-00-sandbox-design` |
| M00-02 | Satisfied (`PASS` on backlog; artifacts on `main`) |
| M01-00 on `main` | Present (`docs/tasks/M01-00.md`, validation note) |
| M01-00 merge commit | `d631f406864b7d1f3fbba34d5c2531044a238aab` (parents include feature tip `4b2aec89474fff3e384726f822a68b7cb7e764c3`; committer GitHub) |
| PR number | Not present in local merge commit message; not invented |

### Design outputs produced

| Document | Role |
|----------|------|
| [`../architecture/sandbox-threat-model.md`](../architecture/sandbox-threat-model.md) | Assets, boundaries, threats, controls, negative tests |
| [`../architecture/sandbox-design.md`](../architecture/sandbox-design.md) | Architecture, tech assessment, contract mapping, M03-01 PoC |
| [`../tasks/M03-00.md`](../tasks/M03-00.md) | Task record |

### Optional presence checks (not selection criteria)

| Tool | Observation |
|------|-------------|
| Podman | Not found on PATH |
| Docker | Client present; version observed |
| `unshare` | Present |

**Assumption:** Presence of Docker does not imply rootless, correctly configured, or acceptable isolation.

## Alternatives considered

1. Rootless Podman (recommended candidate for M03-01; unvalidated; not currently on PATH).
2. Rootless Docker (fallback only if proven rootless and socket-free).
3. Bespoke namespace/bind-mount tooling (flexible; high misconfiguration risk).
4. Disposable VM (stronger isolation; higher overhead; harder ACP stdio).

## Assumptions

1. WSL2 Linux user namespaces and cgroups are usable for a future PoC, subject to M03-01 proof.
2. ACP stdio can be supervised from a host-side launcher without mounting host credentials.
3. Synthetic projects suffice for first negative tests.
4. Human-only Git integration remains mandatory during MVP.

## Remaining blockers before SANDBOX PASS

1. Implement and run M03-01 disposable PoC with negative tests P1–P8.
2. Produce reproducible evidence packs.
3. Resolve unresolved decisions in the design doc (runtime choice on this host, DNS policy, ACP transport supervision).
4. Complete M03-02 gate review with independent enforcement evidence.

## Criterion results for M03-00

| Criterion | Status |
|-----------|--------|
| Documentation of threat model | PASS (design artifact) |
| Documentation of architecture and PoC plan | PASS (design artifact) |
| External isolation enforced on host | NOT_TESTED |
| Negative filesystem/network tests executed | NOT_TESTED |
| SANDBOX gate | NOT_TESTED |
| Live ACP session | NOT_TESTED (forbidden here) |

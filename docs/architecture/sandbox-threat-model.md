# Sandbox threat model (M03-00)

**Status:** Design intent only. No live sandbox was created or tested in M03-00.  
**SANDBOX gate:** `NOT_TESTED`

## 1. Protected assets

| Asset | Why it matters |
|-------|----------------|
| Host filesystem outside the authorized project workspace | Prevents host compromise and data theft |
| Other Engineering OS / developer projects | Prevents cross-project contamination |
| Host credentials (cloud CLIs, package tokens, browser cookies) | Prevents lateral movement and spend abuse |
| SSH agent / keys | Prevents unauthorized remote access |
| GitHub credentials and tokens | Prevents unauthorized repository mutation |
| Container/VM runtime sockets | Prevents breakout to host orchestration |
| Network reachability | Prevents exfiltration and supply-chain pulls without approval |
| Audit evidence integrity | Prevents false PASS claims |

## 2. Trust boundaries

| Boundary | Inside | Outside | Enforcement expectation |
|----------|--------|---------|-------------------------|
| TB0 Owner | Human decisions | All automation | Process / Git authority |
| TB1 Policy decision | Supervisor evaluates contracts/approvals | Executor | Host-side launcher, not the agent |
| TB2 Sandbox perimeter | Executor process tree | Host + other projects | External runtime controls |
| TB3 Project workspace | Synthetic/disposable mount | Sibling projects | Mount allow-list |
| TB4 Network edge | Denied-by-default namespace | Internet / LAN | Egress filter + DNS policy |
| TB5 Integration plane | GitHub/CI identities | Executor | Credentials never mounted into sandbox |

Application-level restrictions (prompts, `AGENTS.md`, CLI `--sandbox` flags, cwd) sit **inside** TB2 and are **not** equivalent to host-enforced isolation.

## 3. Adversaries and realistic failures

| Actor / failure | Intent or cause |
|-----------------|-----------------|
| Prompt-injected / misaligned agent | Attempts escape, exfiltration, or privilege abuse |
| Compromised tool plugin / MCP | Uses granted tools beyond intended scope |
| Operator error | Wrong mounts, overly broad network allow-list |
| Shared host misconfiguration | Rootful daemon, writable docker.sock, inherited HOME |
| Residual kernel/runtime bugs | Container escape class vulnerabilities |
| Evidence tampering | Agent edits logs inside the workspace |

## 4. Attack surfaces

1. Writable mounts that include host HOME, SSH, cloud config, or sibling repos.
2. Inherited environment variables carrying tokens.
3. SSH agent socket forwarding.
4. Docker/Podman socket mounted into the executor.
5. Network allow-lists that include metadata endpoints or package registries without approval.
6. DNS resolvers that bypass intended egress filters.
7. Privileged or root execution inside the sandbox.
8. Host PID/IPC namespaces shared unintentionally.
9. Persistent volumes reused across projects.
10. ACP stdio/control channel that can request host-side actions outside the sandbox.

## 5. Credential leakage paths

| Path | Example | Required control |
|------|---------|------------------|
| HOME inheritance | Cloud SDK configs under home | Empty/minimal HOME inside sandbox |
| Env inheritance | API keys in process environment | Explicit env allow-list; default drop |
| SSH agent | `SSH_AUTH_SOCK` | Never forward into executor |
| Git credentials | helper caches, `gh` auth store | Keep GitHub auth on host integration plane |
| Runtime socket | `docker.sock` / podman socket | Never mount into executor |
| Workspace secrets | `.env` committed or copied | Synthetic canaries only in PoC; deny secret paths |

## 6. Residual risks (not eliminated by this design)

- Kernel or runtime zero-days enabling container escape.
- Covert channels via timing/storage on a shared host.
- Owner mistakenly approving a broad network or mount exception.
- ACP client on the host performing privileged actions *outside* the sandbox while claiming sandboxed execution.
- Incomplete evidence sanitization leading to secret publication in a public repo.

## 7. Threat-to-control matrix

| Threat ID | Threat | Primary controls | Negative test theme |
|-----------|--------|------------------|---------------------|
| T1 | Write outside workspace | RO rootfs + bind mount allow-list | Write to path outside workspace fails |
| T2 | Read sibling project | Per-project disposable mount; no sibling bind | Open second project path fails |
| T3 | Read host secrets | No HOME/secrets mounts; env scrub | Read canary secret path fails |
| T4 | Use SSH agent | Drop `SSH_AUTH_SOCK`; no agent mount | SSH auth via agent fails |
| T5 | Use GitHub host creds | No gh/git credential mounts; Git writes host-side only | GitHub API/git push from sandbox fails |
| T6 | Docker breakout via socket | Deny runtime sockets | Access to socket path fails |
| T7 | Default network exfil | Network namespace + default-deny egress | HTTPS to public endpoint fails |
| T8 | DNS bypass | Controlled resolvers / no raw resolver escape | Resolution/egress bypass attempt fails or is blocked |
| T9 | Resource exhaustion | CPU/memory/pids/time/disk quotas | Over-limit process is killed |
| T10 | Cross-run contamination | Disposable workspace + cleanup | Post-run workspace removed; no leftover mounts |
| T11 | Fake isolation via CLI flags | Supervisor refuses execution without external launcher evidence | Claim based only on `--sandbox` is rejected |
| T12 | Prompt/policy-only “deny” | External enforcement independent of prompts | Agent instructed to escape still fails host controls |

## 8. Verifiable negative tests (design targets for M03-01)

All tests use **synthetic paths and canary files**, never real host secrets.

| Test ID | Assertion | PASS requires |
|---------|-----------|---------------|
| N1 | Denied write outside workspace | Non-zero exit + unchanged canary outside mount |
| N2 | Denied read of second synthetic project | Access error; no content returned |
| N3 | Denied read of host-secret canary | Access error |
| N4 | Denied network by default | Connection/timeout failure to blocked destination |
| N5 | Denied runtime socket | Socket open fails |
| N6 | Denied SSH agent use | Operation fails without agent |
| N7 | Resource/time limit enforced | Process terminated by limit |
| N8 | Cleanup after stop/crash | Workspace directory and cgroup/netns artifacts removed |

Recording a test plan is **not** evidence of enforcement. M03-02 remains `NOT_TESTED` until independent enforcement tests succeed.

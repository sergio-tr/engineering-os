# M03-01 validation — External sandbox PoC (closure record)

**Explicit statements:**

- M03-01 is proposed **PASS** as a synthetic PoC only.
- The SANDBOX gate remains **NOT_TESTED**.
- Live Cursor ACP remains **BLOCKED** (depends on M03-02).
- Historical evidence files were **not** rewritten during closure.
- This document consolidates Owner-reported executions; it is **not** the M03-02 independent audit report.

## Provenance classes

| Class | Meaning |
|-------|---------|
| Owner-reported | Runtime JSON archived by Owner after triple-gate execute |
| Locally verified (closure) | File presence + SHA-256 manifest check during consolidation |
| Not independently audited | Content semantics / threat coverage pending M03-02 |

## Code SHAs

| Label | SHA |
|-------|-----|
| B2 merge on `main` | `0f68c17501dc1b29e23cf5148189e13679565838` |
| B3 merge on `main` (PR #9) | `b47eb8ba1340aab44d5f234dc58687048c5b6619` |

PR #9 CI/check/review status: **not verified** in this closure (no usable GitHub check entries observed). Local `main` contains `b47eb8ba…`.

## Catalog and security-control results (Owner-reported)

| Evidence | Result | Code context |
|----------|--------|--------------|
| P1 | PASS | Pre-B2 / B1 harness |
| P2–P4 | PASS | Pre-B2 / B1 harness |
| P5 | PASS | Pre-B2 / B1 harness |
| P6 initial | Partial (CPU NOT_TESTED) | Pre-B2 |
| P6-B2 | PASS (memory/PIDs/time/CPU); caps PASS; userns FAIL | `0f68c175…` |
| P7 | PASS | Pre-B2 / B1 harness |
| P8 | PASS | Pre-B2 / B1 harness |
| B3 identity | PASS (`userns_keep_id`, caps); `p6_executed=false` | `b47eb8ba…` |

### B2 CPU / capability highlights (Owner-reported)

- `cpu.max`: `50000 100000` (0.50 CPUs)
- Throttle delta: `nr_throttled +50`
- CapPrm/Eff/Bnd/Amb: zero; NoNewPrivs=1
- Userns: FAIL (`id_map_does_not_match_host_identity`) — defect corrected in B3; FAIL record retained

### B3 identity highlights (Owner-reported)

- Host-side `/proc/<pid>/{uid,gid}_map` with `reader_context=launching_host`
- PID linked to container; stable `starttime`
- Effective UID/GID `1000:1001`; maps `1000→1000`, `1001→1001`
- Marker ownership `1000:1001`
- Cleanup verified; no residual `eos-sandbox-poc-*`

## Evidence integrity (locally verified at closure)

Store: `~/.local/share/engineering-os/evidence/m03-01/`

| File | SHA-256 |
|------|---------|
| `p1.json` | `3fe9481223de3f58af68ae2c66121ed1692aea74aa7cf2cf8ce79f3e68862d7e` |
| `p234.json` | `8576372a760bb6ae8894a64ca8294fad6d44ed3e7817930aaaaa4844c673693b` |
| `p5.json` | `1876bfb50db780e528e72ad41fc8b21adf88f4162253eccda416282137cf6949` |
| `p6.json` | `2f37147e24cfceb0aa280dd81a60e75205f72189ebb560af59698762a80097be` |
| `p6-b2.json` | `51f92e993eb8c6b15f74540fd935315ec71fcc4bf61607f5b8fe55857c88dacd` |
| `p7.json` | `0f16a4f28e30546ae1c22d875adc6e0e5418f2813fd5811b33855a2f0bb6d31d` |
| `p8.json` | `4abcdebe44207d513026ca9d09cc362885789f436c9a6a1f14a7d8bb718953bd` |
| `userns-b3.json` | `237c04a18d7abef3b602bb3f20263f70f93a0f4c9a397adc89aa5c9abf01b35f` |

`sha256sum -c evidence-manifest.sha256` → all OK at consolidation.

## Mapping to PoC negative tests (design N1–N8)

| Design ID | Covered by M03-01? | Evidence |
|-----------|--------------------|----------|
| N1 outside write | Yes | P2 |
| N2 sibling project | Yes | P3 |
| N3 host-secret canary | Yes | P4 |
| N4 network deny | Yes | P5 |
| N5 runtime socket | Yes | P8 |
| N6 SSH agent | **No dedicated negative test** | Env scrub configured; N6 remains for M03-02 |
| N7 resource/time | Yes (CPU/mem/PIDs/time) | P6 / P6-B2; **disk quota not specifically attributed** |
| N8 cleanup | Yes | P7 (+ B2/B3 cleanups) |

## Residual items deferred to M03-02

1. Workspace **disk** quota behavioral proof.
2. Explicit **SSH agent** and **GitHub credential** negative tests (N6 / T4 / T5).
3. Explicit **PID/IPC** namespace isolation proof.
4. Independent review of evidence integrity, false positives, and threat coverage T1–T12.
5. Future ACP launcher path compatibility **without** starting live ACP.
6. Reproducibility audit on the declared WSL2 environment by an independent reviewer.

## Closure validation (this documentary pass)

| Check | Result |
|-------|--------|
| Evidence files present | PASS (8/8) |
| SHA-256 manifest | PASS (`sha256sum -c`) |
| Container execute during closure | **Not performed** |
| SANDBOX gate | **NOT_TESTED** |

## Decision

M03-01 synthetic PoC: **PASS** (documentary consolidation).

Next: execute `docs/tasks/M03-02.md` / `docs/validation/M03-02-independent-audit.md` as an **independent** audit; do not treat this file as that audit.

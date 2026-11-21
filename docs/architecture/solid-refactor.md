# Modular SOLID architecture (EOS-13)

## Dependency direction

```
interfaces (CLI / HTTP / dashboard)
    -> application (use cases, orchestration, ControlPlane facade)
        -> domain + ports
infrastructure adapters implement ports and are wired only in bootstrap.py
```

Domain and ports must not import SQLite, HTTP, Podman, or Cursor.

## Composition root

`engineering_os.bootstrap.build_dependencies` constructs concrete adapters and returns
`ControlPlaneDependencies`. `ControlPlane.from_dependencies` / `open_control_plane`
apply the bundle. Legacy keyword construction remains for tests.

## Persistence

SQLite lives under `infrastructure/persistence/sqlite/` with focused repositories and a
shared connection/transaction boundary. `infrastructure/sqlite_repo.py` is a thin
compatibility shim exporting `Repository`.

## Runtime packaging

| Package | Responsibility |
|---------|----------------|
| `infrastructure/network/` | Egress broker, policy, probes |
| `infrastructure/runtime/cursor/` | Cursor image, launcher, smoke, preflight |
| `infrastructure/runtime/oci/` | Podman / OCI process transport |
| `infrastructure/runtime/sandbox/` | Sandbox launcher/spec |
| `infrastructure/acp/` | ACP protocol, sessions, ACPX |
| `infrastructure/integrations/` | GitHub, Paperclip, OpenClaw |
| `infrastructure/security/` | Credentials, runtime authorization |

Old import paths remain as compatibility shims.

## Interfaces

- HTTP capability routes: `interfaces/http/routes/`
- CLI package: `interfaces/cli/` (`app.py` + future command modules)

## Trust boundaries (unchanged)

- Owner triple-gate for real Podman / live Cursor
- Deny-by-default network; UDS broker; no host-network fallback
- Credential redaction; no secrets in SQLite/argv/logs
- Synthetic vs real evidence classes remain distinct
- Dashboard never exposes unrestricted live launch

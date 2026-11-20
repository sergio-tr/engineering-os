# Roadmap — Engineering OS

## Numbering vs execution order

Milestone numbers (`M00`…`M08`) identify work domains. They do **not** necessarily match real execution order. Effective order is defined by [backlog](backlog.yaml) dependencies and blocking gates.

In particular, isolation tests (**M03**) must pass **before** autonomous execution on real projects is allowed, even though Cursor ACP validation (**M01**) and OpenClaw/ACPX (**M02**) may start in parallel at discovery level.

## Milestones

| ID | Name | Goal |
|----|------|------|
| M00 | Documentation, baseline, and contracts | Documentary foundation, governance, and canonical contracts |
| M01 | Cursor ACP | Validate the Cursor CLI ACP executor |
| M02 | OpenClaw and ACPX | Validate coordination and ACP integration via OpenClaw/ACPX |
| M03 | Sandbox and isolation | Demonstrate effective external isolation |
| M04 | Paperclip and organization | Enterprise organization, goals, and tracking |
| M05 | GitHub, CI, and reconciliation | Integration authority and cycle closure |
| M06 | Persistence, recovery, and multi-project | Durability, recovery, and multi-project segregation |
| M07 | Mobile executive experience | Executive interface usable on mobile |
| M08 | Hardening, pilot, and operations | Controlled pilot and continuous operations |

## Blocking gates

No later increment may declare operational autonomy on real projects while these gates fail or remain open:

| Gate | Meaning |
|------|---------|
| ACP | Cursor CLI ACP executor demonstrates a controlled session and delivery |
| ACPX | OpenClaw ↔ ACP executor integration is validated or discarded with evidence |
| SANDBOX | Effective external isolation exists; prompts/cwd/rules are not enough |
| PAPERCLIP | Organizational layer can govern goals, agents, and costs |
| GITHUB | Commits/PRs/checks/merges remain under GitHub + human authority |
| RECOVERY | Persistence and recovery allow resume without state corruption |
| MULTI_PROJECT | Segregation between projects is effective and verifiable |

## Conditional exception: M02-01

`M02-01` (authorized OpenClaw fix) runs **only** if diagnosis shows a necessary repair and the Owner authorizes it. The backlog YAML does not express conditional dependencies: `M02-02` depends on `M02-00` and `M01-01`, **not** on `M02-01`. If `M02-01` is unnecessary, it does not block progress.

## Dependencies (view)

```mermaid
flowchart TD
  M0000[M00-00 Diagnostic] --> M0001[M00-01 Documentation]
  M0000 --> M0100[M01-00 ACP discovery]
  M0000 --> M0200[M02-00 OpenClaw diagnosis]
  M0001 --> M0002[M00-02 Contracts]

  M0002 --> M0300[M03-00 Sandbox design]
  M0100 --> M0300
  M0300 --> M0301[M03-01 Isolation PoC]
  M0301 --> M0302[M03-02 SANDBOX gate]

  M0302 --> M0101[M01-01 Controlled ACP session]
  M0100 --> M0101
  M0101 --> M0102[M01-02 ACP gate]

  M0200 -.->|conditional| M0201[M02-01 Authorized repair]
  M0200 --> M0202[M02-02 ACPX validation]
  M0101 --> M0202
  M0202 --> M0203[M02-03 ACPX gate]
  M0302 --> M0203

  M0002 --> M0400[M04-00 Paperclip evaluation]
  M0400 --> M0401[M04-01 Minimal organization]
  M0401 --> M0402[M04-02 PAPERCLIP gate]
  M0203 --> M0402

  M0002 --> M0500[M05-00 GitHub contract]
  M0302 --> M0500
  M0500 --> M0501[M05-01 PR and CI]
  M0101 --> M0501
  M0501 --> M0502[M05-02 GITHUB gate]
  M0402 --> M0502

  M0203 --> M0600[M06-00 Persistence]
  M0402 --> M0600
  M0502 --> M0600
  M0600 --> M0601[M06-01 RECOVERY gate]
  M0601 --> M0602[M06-02 MULTI_PROJECT gate]
  M0302 --> M0602

  M0401 --> M0700[M07-00 Executive UX]
  M0601 --> M0700
  M0700 --> M0701[M07-01 Mobile UX]
  M0602 --> M0701

  M0701 --> M0800[M08-00 Hardening]
  M0800 --> M0801[M08-01 Pilot]
  M0801 --> M0802[M08-02 Continuous operations]
```

## M03 security rule

Until `M03-02` (SANDBOX gate) is `PASS` with external evidence, **no** autonomous execution on real projects is authorized. M01/M02 discovery may continue in a controlled, low-risk mode without treating the host environment as sufficient.

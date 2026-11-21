"""SQLite schema DDL for the Engineering OS control plane."""

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS projects (
  project_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  repository_identity TEXT NOT NULL,
  status TEXT NOT NULL,
  isolation_requirements TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS goals (
  goal_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(project_id),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  priority INTEGER NOT NULL,
  approval_state TEXT NOT NULL,
  lifecycle_state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS tasks (
  task_id TEXT PRIMARY KEY,
  goal_id TEXT NOT NULL REFERENCES goals(goal_id),
  project_id TEXT NOT NULL REFERENCES projects(project_id),
  description TEXT NOT NULL,
  depends_on_json TEXT NOT NULL,
  assigned_agent_ref TEXT NOT NULL,
  execution_eligible INTEGER NOT NULL,
  lifecycle_state TEXT NOT NULL,
  blocked_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS executions (
  execution_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  project_id TEXT NOT NULL REFERENCES projects(project_id),
  execution_contract_ref TEXT NOT NULL,
  runner_type TEXT NOT NULL,
  attempt_number INTEGER NOT NULL,
  status TEXT NOT NULL,
  failure_reason TEXT,
  evidence_refs_json TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  started_at TEXT,
  ended_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  integration_state TEXT,
  synthetic INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  requested_action TEXT NOT NULL,
  scope TEXT NOT NULL,
  approver_reference TEXT NOT NULL,
  decision TEXT NOT NULL,
  expires_at TEXT,
  audit_metadata_json TEXT NOT NULL,
  goal_id TEXT,
  project_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operational_events (
  event_id TEXT PRIMARY KEY,
  aggregate_type TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orchestration_claims (
  project_id TEXT PRIMARY KEY,
  execution_id TEXT,
  task_id TEXT,
  claimed_at TEXT,
  claim_token TEXT
);

CREATE INDEX IF NOT EXISTS idx_tasks_project ON tasks(project_id, lifecycle_state);
CREATE INDEX IF NOT EXISTS idx_exec_task ON executions(task_id, attempt_number);
CREATE INDEX IF NOT EXISTS idx_events_agg ON operational_events(aggregate_type, aggregate_id);

CREATE TABLE IF NOT EXISTS github_connections (
  project_id TEXT PRIMARY KEY REFERENCES projects(project_id),
  owner TEXT NOT NULL,
  repo TEXT NOT NULL,
  repository_identity TEXT NOT NULL,
  api_base TEXT NOT NULL,
  default_branch TEXT,
  head_sha TEXT,
  last_sync_at TEXT,
  last_error_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS execution_pr_links (
  execution_id TEXT PRIMARY KEY REFERENCES executions(execution_id),
  project_id TEXT NOT NULL REFERENCES projects(project_id),
  repository_identity TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  expected_base_ref TEXT,
  expected_head_sha TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(project_id, repository_identity, pr_number)
);

CREATE TABLE IF NOT EXISTS github_observations (
  observation_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(project_id),
  execution_id TEXT,
  repository_identity TEXT NOT NULL,
  pr_number INTEGER,
  evidence_class TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  stale INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_gh_obs_project ON github_observations(project_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_pr_links_project ON execution_pr_links(project_id);

CREATE TABLE IF NOT EXISTS external_identity_mappings (
  mapping_id TEXT PRIMARY KEY,
  system_name TEXT NOT NULL,
  company_id TEXT,
  local_kind TEXT NOT NULL,
  local_id TEXT NOT NULL,
  external_id TEXT NOT NULL,
  external_revision TEXT,
  correlation_id TEXT,
  last_sync_at TEXT,
  evidence_class TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(system_name, local_kind, local_id),
  UNIQUE(system_name, company_id, local_kind, external_id)
);

CREATE TABLE IF NOT EXISTS integration_observations (
  observation_id TEXT PRIMARY KEY,
  system_name TEXT NOT NULL,
  project_id TEXT,
  company_id TEXT,
  evidence_class TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  stale INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ext_map_local ON external_identity_mappings(system_name, local_kind, local_id);
CREATE INDEX IF NOT EXISTS idx_int_obs_system ON integration_observations(system_name, observed_at);

CREATE TABLE IF NOT EXISTS acp_sessions (
  session_id TEXT PRIMARY KEY,
  execution_id TEXT NOT NULL UNIQUE,
  project_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  acp_backend TEXT NOT NULL,
  transport_type TEXT NOT NULL,
  protocol_version INTEGER NOT NULL,
  status TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  last_event_sequence INTEGER NOT NULL DEFAULT 0,
  cancellation_state TEXT,
  failure_reason TEXT,
  evidence_refs_json TEXT NOT NULL,
  runtime_provenance_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT,
  last_activity_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS acp_session_events (
  event_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES acp_sessions(session_id),
  execution_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  dedupe_key TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  UNIQUE(session_id, dedupe_key)
);

CREATE INDEX IF NOT EXISTS idx_acp_sess_project ON acp_sessions(project_id, status);
CREATE INDEX IF NOT EXISTS idx_acp_evt_session ON acp_session_events(session_id, sequence);

CREATE TABLE IF NOT EXISTS runtime_preparations (
  preparation_id TEXT PRIMARY KEY,
  execution_id TEXT NOT NULL UNIQUE,
  project_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  spec_id TEXT NOT NULL,
  spec_json TEXT NOT NULL,
  acpx_session_id TEXT,
  cursor_session_id TEXT,
  readiness_json TEXT NOT NULL,
  authorization_state TEXT NOT NULL,
  image_digest TEXT NOT NULL,
  status TEXT NOT NULL,
  mode TEXT NOT NULL,
  blocked_reasons_json TEXT NOT NULL,
  launch_plan_json TEXT NOT NULL,
  evidence_refs_json TEXT NOT NULL,
  cleanup_status TEXT,
  failure_reason TEXT,
  correlation_id TEXT NOT NULL,
  provenance_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_rtprep_project ON runtime_preparations(project_id, status);

CREATE TABLE IF NOT EXISTS oci_fixture_runs (
  run_id TEXT PRIMARY KEY,
  execution_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  acp_session_id TEXT,
  container_id TEXT,
  code_revision TEXT NOT NULL,
  image_ref TEXT NOT NULL,
  image_digest TEXT,
  applied_limits_json TEXT NOT NULL,
  runtime_controls_json TEXT NOT NULL,
  exit_code INTEGER,
  timeout_or_cancel TEXT,
  exchange_summary_json TEXT NOT NULL,
  host_observations_json TEXT NOT NULL,
  cleanup_status TEXT,
  evidence_refs_json TEXT NOT NULL,
  evidence_hashes_json TEXT NOT NULL,
  provenance TEXT NOT NULL,
  status TEXT NOT NULL,
  failure_reason TEXT,
  correlation_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_oci_runs_project ON oci_fixture_runs(project_id, created_at);

CREATE TABLE IF NOT EXISTS cursor_preparations (
  preparation_id TEXT PRIMARY KEY,
  execution_id TEXT NOT NULL UNIQUE,
  project_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  cursor_version TEXT,
  image_digest TEXT,
  agent_id TEXT NOT NULL,
  acp_session_id TEXT,
  sandbox_identity TEXT,
  authorization_ref TEXT,
  network_policy_id TEXT,
  credential_provider_ref TEXT,
  resource_ceilings_json TEXT NOT NULL,
  workspace_json TEXT NOT NULL,
  acpx_config_json TEXT NOT NULL,
  blockers_json TEXT NOT NULL,
  status TEXT NOT NULL,
  mode TEXT NOT NULL,
  provenance TEXT NOT NULL,
  evidence_refs_json TEXT NOT NULL,
  cleanup_status TEXT,
  failure_reason TEXT,
  correlation_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_curprep_project ON cursor_preparations(project_id, status);
"""

(() => {
  "use strict";

  let csrfToken = null;
  let selectedProjectId = null;
  let selectedExecutionId = null;

  const $ = (id) => document.getElementById(id);

  function toast(msg, isError) {
    const el = $("toast");
    el.hidden = false;
    el.textContent = msg;
    el.classList.toggle("error", !!isError);
    clearTimeout(toast._t);
    toast._t = setTimeout(() => {
      el.hidden = true;
    }, 4200);
  }

  function cookie(name) {
    const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return m ? decodeURIComponent(m[1]) : null;
  }

  async function ensureCsrf() {
    const res = await fetch("/api/csrf", { credentials: "same-origin" });
    const data = await res.json();
    csrfToken = data.csrf_token || cookie("eos_csrf");
    return csrfToken;
  }

  async function api(path, options = {}) {
    const opts = {
      credentials: "same-origin",
      headers: { Accept: "application/json", ...(options.headers || {}) },
      ...options,
    };
    if (opts.method && opts.method !== "GET") {
      if (!csrfToken) await ensureCsrf();
      opts.headers["X-CSRF-Token"] = csrfToken;
      opts.headers["Content-Type"] = "application/json";
    }
    const res = await fetch(path, opts);
    const text = await res.text();
    let data;
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { ok: false, error: text || "invalid_json" };
    }
    if (!res.ok) {
      const err = new Error((data && data.error) || res.statusText);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  function badge(state) {
    return `<span class="badge ${state || ""}">${state || "—"}</span>`;
  }

  function renderStats(overview) {
    const by = overview.tasks_by_state || {};
    const items = [
      ["Projects", overview.projects],
      ["Active goals", overview.active_goals],
      ["Pending approvals", overview.pending_approvals],
      ["READY", by.READY || 0],
      ["RUNNING", by.RUNNING || 0],
      ["BLOCKED / FAILED", (by.BLOCKED || 0) + (by.FAILED || 0)],
      ["SANDBOX gate", overview.sandbox_gate],
    ];
    $("stats").innerHTML = items
      .map(
        ([label, value]) =>
          `<div class="stat"><div class="label">${label}</div><div class="value">${value}</div></div>`
      )
      .join("");
  }

  function renderProjects(projects) {
    const ul = $("project-list");
    if (!projects.length) {
      ul.innerHTML = `<li class="empty">No projects yet</li>`;
      return;
    }
    ul.innerHTML = projects
      .map(
        (p) => `<li>
        <div class="row"><strong>${escapeHtml(p.name)}</strong> ${badge(p.status)}</div>
        <div class="meta">${escapeHtml(p.project_id)} · ${escapeHtml(p.repository_identity)}</div>
        <button type="button" data-open-project="${escapeHtml(p.project_id)}">Open</button>
      </li>`
      )
      .join("");
  }

  function renderGoals(goals) {
    const ul = $("goal-list");
    if (!goals.length) {
      ul.innerHTML = `<li class="empty">No goals</li>`;
      return;
    }
    ul.innerHTML = goals
      .map(
        (g) => `<li>
        <div class="row"><strong>${escapeHtml(g.title)}</strong> ${badge(g.lifecycle_state)}</div>
        <div class="meta">${escapeHtml(g.goal_id)} · approval ${escapeHtml(g.approval_state)}</div>
        <div class="row">
          <button type="button" data-use-goal="${escapeHtml(g.goal_id)}">Use for tasks</button>
          ${
            g.lifecycle_state === "DRAFT" || g.lifecycle_state === "PENDING_APPROVAL"
              ? `<button type="button" data-approve-goal="${escapeHtml(g.goal_id)}">Synthetic approve</button>`
              : ""
          }
        </div>
      </li>`
      )
      .join("");
  }

  function renderTasks(tasks) {
    const ul = $("task-list");
    if (!tasks.length) {
      ul.innerHTML = `<li class="empty">No tasks</li>`;
      return;
    }
    ul.innerHTML = tasks
      .map((t) => {
        const reason = t.ineligibility_reason
          ? `<div class="meta">Not eligible: ${escapeHtml(t.ineligibility_reason)}</div>`
          : "";
        const deps = (t.depends_on || []).length
          ? `<div class="meta">Depends on: ${(t.depends_on || []).map(escapeHtml).join(", ")}</div>`
          : "";
        const run =
          t.lifecycle_state === "READY"
            ? `<button type="button" class="synth" data-run-task="${escapeHtml(t.task_id)}">Run SYNTHETIC</button>`
            : "";
        return `<li>
          <div class="row"><strong>${escapeHtml(t.description)}</strong> ${badge(t.lifecycle_state)}</div>
          <div class="meta">${escapeHtml(t.task_id)}</div>
          ${deps}${reason}
          <div class="row">${run}</div>
        </li>`;
      })
      .join("");
  }

  function renderExecutions(executions) {
    const ul = $("execution-list");
    if (!executions.length) {
      ul.innerHTML = `<li class="empty">No executions</li>`;
      return;
    }
    ul.innerHTML = executions
      .slice()
      .reverse()
      .map(
        (e) => `<li>
        <div class="row">
          <strong>${escapeHtml(e.execution_id)}</strong>
          ${badge(e.status)}
          ${e.synthetic ? '<span class="badge SYNTHETIC">SYNTHETIC</span>' : ""}
        </div>
        <div class="meta">task ${escapeHtml(e.task_id)} · attempt ${e.attempt_number} · ${escapeHtml(e.runner_type)}</div>
        <button type="button" data-open-exec="${escapeHtml(e.execution_id)}">Details</button>
      </li>`
      )
      .join("");
  }

  function renderEvents(events) {
    const ul = $("event-list");
    if (!events.length) {
      ul.innerHTML = `<li>No events</li>`;
      return;
    }
    ul.innerHTML = events
      .slice()
      .reverse()
      .map(
        (e) =>
          `<li>${escapeHtml(e.timestamp)} · ${escapeHtml(e.event_type)} · ${escapeHtml(e.aggregate_type)}/${escapeHtml(e.aggregate_id)}</li>`
      )
      .join("");
  }

  function renderOrchestration(orch) {
    const el = $("orch-panel");
    if (!orch) {
      el.textContent = "";
      return;
    }
    const active = orch.active_execution;
    el.innerHTML = `
      <div class="row"><strong>Orchestration</strong> ${badge(orch.sandbox_gate)}</div>
      <div class="meta">Next eligible: ${escapeHtml(orch.next_eligible_task || "none")}</div>
      <div class="meta">Active: ${
        active
          ? escapeHtml(active.execution_id) + " · " + escapeHtml(active.status)
          : "none"
      }</div>
      <div class="row" style="margin-top:0.5rem">
        <button type="button" id="btn-tick" class="synth">Orchestrate tick</button>
        <button type="button" id="btn-orch-full" class="synth">Full synthetic lifecycle</button>
        <button type="button" id="btn-recover">Recover</button>
      </div>
    `;
  }

  function renderGitHub(github) {
    const el = $("github-panel");
    if (!github || !github.connection) {
      el.classList.add("empty");
      el.textContent = "No GitHub connection for this project";
      return;
    }
    el.classList.remove("empty");
    const c = github.connection;
    const latest = github.latest_observation;
    const evidence = latest
      ? latest.stale
        ? "CACHED"
        : latest.evidence_class
      : "—";
    el.innerHTML = `
      <div class="row"><strong>${escapeHtml(c.repository_identity)}</strong> ${badge(evidence)}</div>
      <div class="meta">Default branch: ${escapeHtml(c.default_branch || "—")} · Head ${escapeHtml(c.head_sha || "—")}</div>
      <div class="meta">Last sync: ${escapeHtml(c.last_sync_at || "never")}</div>
      <div class="meta">Token configured: ${github.token_configured ? "yes (not displayed)" : "no (public repos only)"}</div>
      <div class="meta">Live ACP: disabled · SANDBOX ${escapeHtml(github.sandbox_gate || "")}</div>
      ${
        c.last_error
          ? `<div class="meta">API error: ${escapeHtml(JSON.stringify(c.last_error))}</div>`
          : ""
      }
      <div class="meta">PR links: ${(github.pr_links || []).length}</div>
    `;
  }

  function renderGitHubPrs(payload) {
    const ul = $("github-pr-list");
    const prs = (payload && payload.pull_requests) || [];
    const cls = (payload && payload.evidence_class) || "UNVERIFIED";
    if (!prs.length) {
      ul.innerHTML = `<li class="empty">No pull requests (${escapeHtml(cls)})</li>`;
      return;
    }
    ul.innerHTML = prs
      .map(
        (pr) => `<li>
        <div class="row"><strong>#${escapeHtml(pr.pr_number)}</strong> ${badge(pr.pr_state)} ${badge(pr.evidence_class || cls)}</div>
        <div class="meta">${escapeHtml(pr.title || "")}</div>
        <div class="meta">CI ${escapeHtml(pr.ci_status || "n/a")} · Reviews ${escapeHtml(pr.review_status || "n/a")} · Merge ${escapeHtml(pr.merge_commit_sha || "—")}</div>
      </li>`
      )
      .join("");
  }

  async function openProject(projectId) {
    selectedProjectId = projectId;
    $("goal-project-id").value = projectId;
    $("github-project-id").value = projectId;
    const detail = await api(`/api/projects/${encodeURIComponent(projectId)}`);
    const p = detail.project;
    $("project-detail").classList.remove("empty");
    $("project-detail").innerHTML = `
      <div class="row"><strong>${escapeHtml(p.name)}</strong> ${badge(p.status)}</div>
      <div class="meta">${escapeHtml(p.project_id)}</div>
      <div class="meta">${escapeHtml(p.repository_identity)}</div>
      <div class="meta">Isolation: ${escapeHtml(p.isolation_requirements)}</div>
    `;
    renderGoals(detail.goals || []);
    renderTasks(
      (detail.tasks || []).map((t) => ({
        ...t,
        ineligibility_reason:
          t.lifecycle_state === "READY" && t.execution_eligible
            ? null
            : t.blocked_reason || `state=${t.lifecycle_state}`,
      }))
    );
    renderExecutions(detail.executions || []);
    renderOrchestration(detail.orchestration);
    renderGitHub(detail.github);
  }

  async function openExecution(executionId) {
    selectedExecutionId = executionId;
    const data = await api(`/api/executions/${encodeURIComponent(executionId)}`);
    const e = data.execution;
    const events = data.events || [];
    $("execution-detail").classList.remove("empty");
    $("execution-detail").innerHTML = `
      <div class="row">
        <strong>${escapeHtml(e.execution_id)}</strong>
        ${badge(e.status)}
        <span class="badge SYNTHETIC">${escapeHtml(data.mode || "SYNTHETIC")}</span>
      </div>
      <div class="meta">Project ${escapeHtml(e.project_id)} · Task ${escapeHtml(e.task_id)}</div>
      <div class="meta">Runner ${escapeHtml(e.runner_type)} · Attempt ${e.attempt_number}</div>
      <div class="meta">Integration: ${escapeHtml(e.integration_state || "n/a")}</div>
      <div class="meta">Evidence: ${(e.evidence_refs || []).map(escapeHtml).join(", ") || "none"}</div>
      <div class="meta">Failure: ${escapeHtml(e.failure_reason || "none")}</div>
      <div class="meta">Started ${escapeHtml(e.started_at || "—")} · Ended ${escapeHtml(e.ended_at || "—")}</div>
      <h3 style="margin:0.8rem 0 0.4rem;font-size:0.9rem">Timeline</h3>
      <ul class="list compact">${
        events.length
          ? events
              .map(
                (ev) =>
                  `<li>${escapeHtml(ev.timestamp)} · ${escapeHtml(ev.event_type)}</li>`
              )
              .join("")
          : "<li>No events</li>"
      }</ul>
    `;
  }

  async function refresh() {
    await ensureCsrf();
    const [health, overview, projects, events] = await Promise.all([
      api("/api/health"),
      api("/api/overview"),
      api("/api/projects"),
      api("/api/events?limit=30"),
    ]);
    const pill = $("health-pill");
    pill.textContent = `healthy · SANDBOX ${health.sandbox_gate}`;
    pill.className = "pill " + (health.live_execution_enabled ? "warn" : "ok");
    renderStats(overview);
    renderProjects(projects);
    renderEvents(events);
    if (selectedProjectId) await openProject(selectedProjectId);
    if (selectedExecutionId) await openExecution(selectedExecutionId);
  }

  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  document.body.addEventListener("click", async (ev) => {
    const t = ev.target;
    if (!(t instanceof HTMLElement)) return;
    try {
      if (t.dataset.openProject) await openProject(t.dataset.openProject);
      if (t.dataset.useGoal) $("task-goal-id").value = t.dataset.useGoal;
      if (t.dataset.approveGoal) {
        await api("/api/goals/approve", {
          method: "POST",
          body: JSON.stringify({ goal_id: t.dataset.approveGoal }),
        });
        toast("Goal approved (synthetic Owner decision)");
        await refresh();
      }
      if (t.dataset.runTask) {
        await api("/api/synthetic-executions", {
          method: "POST",
          body: JSON.stringify({ task_id: t.dataset.runTask }),
        });
        toast("SYNTHETIC execution completed");
        await refresh();
      }
      if (t.dataset.openExec) await openExecution(t.dataset.openExec);
      if (t.id === "btn-tick" && selectedProjectId) {
        await api("/api/orchestrate/tick", {
          method: "POST",
          body: JSON.stringify({ project_id: selectedProjectId }),
        });
        toast("Orchestration tick (synthetic)");
        await refresh();
      }
      if (t.id === "btn-orch-full" && selectedProjectId) {
        await api("/api/orchestrate/full", {
          method: "POST",
          body: JSON.stringify({ project_id: selectedProjectId }),
        });
        toast("Full synthetic lifecycle finished");
        await refresh();
      }
      if (t.id === "btn-recover" && selectedProjectId) {
        await api("/api/orchestrate/recover", {
          method: "POST",
          body: JSON.stringify({ project_id: selectedProjectId }),
        });
        toast("Recovery completed");
        await refresh();
      }
    } catch (err) {
      toast(err.message || String(err), true);
    }
  });

  $("form-project").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    try {
      const project = await api("/api/projects", {
        method: "POST",
        body: JSON.stringify({
          name: fd.get("name"),
          repository_identity: fd.get("repository_identity"),
        }),
      });
      ev.target.reset();
      selectedProjectId = project.project_id;
      toast("Project created");
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("form-goal").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    try {
      const goal = await api("/api/goals", {
        method: "POST",
        body: JSON.stringify({
          project_id: fd.get("project_id"),
          title: fd.get("title"),
          description: fd.get("description") || "",
        }),
      });
      $("task-goal-id").value = goal.goal_id;
      toast("Goal created");
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("form-task").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    const raw = String(fd.get("depends_on") || "").trim();
    const depends_on = raw ? raw.split(",").map((s) => s.trim()).filter(Boolean) : [];
    try {
      await api("/api/tasks", {
        method: "POST",
        body: JSON.stringify({
          goal_id: fd.get("goal_id"),
          description: fd.get("description"),
          depends_on,
        }),
      });
      toast("Task created");
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("task-state-filter").addEventListener("change", async (ev) => {
    const state = ev.target.value;
    const q = new URLSearchParams();
    if (selectedProjectId) q.set("project_id", selectedProjectId);
    if (state) q.set("state", state);
    try {
      const tasks = await api("/api/tasks?" + q.toString());
      renderTasks(tasks);
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("btn-refresh").addEventListener("click", () =>
    refresh().catch((err) => toast(err.message, true))
  );
  $("btn-demo").addEventListener("click", async () => {
    try {
      const result = await api("/api/demo", { method: "POST", body: "{}" });
      const project =
        result.project ||
        (result.project_id ? { project_id: result.project_id } : null);
      if (project && project.project_id) {
        selectedProjectId = project.project_id;
      }
      toast(
        result.created
          ? "SYNTHETIC demo seeded into persistent database"
          : "SYNTHETIC demo already present (idempotent)"
      );
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("form-github").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    try {
      await api("/api/github/connect", {
        method: "POST",
        body: JSON.stringify({
          project_id: fd.get("project_id"),
          repository: fd.get("repository"),
        }),
      });
      selectedProjectId = String(fd.get("project_id"));
      toast("GitHub connection configured (read-only)");
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("btn-gh-sync").addEventListener("click", async () => {
    if (!selectedProjectId) return toast("Select a project first", true);
    try {
      await api("/api/github/sync", {
        method: "POST",
        body: JSON.stringify({ project_id: selectedProjectId }),
      });
      toast("GitHub repository synced (read-only)");
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("btn-gh-prs").addEventListener("click", async () => {
    if (!selectedProjectId) return toast("Select a project first", true);
    try {
      const payload = await api(
        `/api/github/prs?project_id=${encodeURIComponent(selectedProjectId)}`
      );
      renderGitHubPrs(payload);
      toast(`Pull requests loaded (${payload.evidence_class || "REAL"})`);
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("form-gh-link").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    try {
      await api("/api/github/link-pr", {
        method: "POST",
        body: JSON.stringify({
          execution_id: fd.get("execution_id"),
          pr_number: Number(fd.get("pr_number")),
        }),
      });
      toast("Execution linked to PR (explicit association)");
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("form-gh-reconcile").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    try {
      const result = await api("/api/github/reconcile", {
        method: "POST",
        body: JSON.stringify({
          execution_id: fd.get("execution_id"),
          complete_task: fd.get("complete_task") === "on",
        }),
      });
      toast(`Reconcile: ${result.action} (${result.evidence_class || ""})`);
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  });

  refresh().catch((err) => toast(err.message, true));
})();

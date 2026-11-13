"""Findings/traces/jobs with disk persistence + workspace catalog."""

from __future__ import annotations

from typing import Any

from isovane_serve import persistence
from isovane_serve import workspaces as workspaces_mod
from isovane_serve.models import Finding, PolicyConfig, ScanJob, Trace, utc_now

AGENTS = [
    {
        "id": "refund",
        "title": "Refund tool gated",
        "meta": "Policy · require confirm",
        "tone": "orange",
        "width": "72%",
    },
    {
        "id": "send",
        "title": "Send blocked from email",
        "meta": "Watch · 3 denies",
        "tone": "blue",
        "width": "38%",
    },
    {
        "id": "scan",
        "title": "Last analyze clean",
        "meta": "Analyze · idle",
        "tone": "idle",
        "width": "14%",
    },
]

SERVICES = [
    {"name": "gate", "command": "poetry run isovane-serve"},
    {"name": "app", "command": "npm run dev"},
]

LOGS = [
    {
        "time": "10:56:02",
        "source": "web",
        "text": "POST /gates DENY send · untrusted email",
        "kind": "ok",
    },
    {"time": "10:56:04", "source": "web", "text": "POST /analyze job_ab12 done · 4 findings"},
    {
        "time": "10:56:09",
        "source": "emails",
        "text": "hunt poison_email_send · DENY",
        "kind": "ok",
    },
    {"time": "10:56:10", "source": "web", "text": "GET /findings?status=open 200", "kind": "ok"},
    {
        "time": "10:56:21",
        "source": "web",
        "text": "POST /fixes/fnd_… copy patch ready",
        "kind": "ok",
    },
]

SERVERS = [
    {"id": "isovane-api", "name": "isovane-api", "port": "8092", "icon": "bolt"},
    {"id": "isovane-app", "name": "isovane-app", "port": "5317", "icon": "s"},
]

FINDINGS: dict[str, Finding] = {}
TRACES: dict[str, Trace] = {}
SCAN_JOBS: dict[str, ScanJob] = {}
AGENT_REGISTRY: dict[str, dict[str, Any]] = {}


def bootstrap_persistence() -> None:
    """Load durable state from ISOVANE_DATA_DIR (idempotent)."""
    FINDINGS.clear()
    FINDINGS.update(persistence.load_findings())
    TRACES.clear()
    TRACES.update(persistence.load_traces())
    SCAN_JOBS.clear()
    SCAN_JOBS.update(persistence.load_jobs())


bootstrap_persistence()


def workspace_by_id(workspace_id: str) -> dict | None:
    return workspaces_mod.store.get(workspace_id)


def list_workspaces() -> list[dict]:
    return workspaces_mod.store.list()


def create_workspace(
    name: str,
    *,
    description: str | None = None,
    folder: str | None = None,
    stack: str | None = None,
    branch: str = "main",
    icon: str | None = None,
) -> dict:
    return workspaces_mod.store.create(
        name,
        description=description,
        folder=folder,
        stack=stack,
        branch=branch,
        icon=icon,
    )


def update_workspace(workspace_id: str, patch: dict[str, Any]) -> dict | None:
    return workspaces_mod.store.update(workspace_id, patch)


def delete_workspace(workspace_id: str) -> bool:
    ok = workspaces_mod.store.delete(workspace_id)
    if not ok:
        return False
    AGENT_REGISTRY.pop(workspace_id, None)
    for fid in [fid for fid, finding in FINDINGS.items() if finding.workspace_id == workspace_id]:
        FINDINGS.pop(fid, None)
    for tid in [tid for tid, trace in TRACES.items() if trace.workspace_id == workspace_id]:
        TRACES.pop(tid, None)
    for jid in [jid for jid, job in SCAN_JOBS.items() if getattr(job, "workspace_id", None) == workspace_id]:
        SCAN_JOBS.pop(jid, None)
    persistence.delete_workspace_artifacts(workspace_id)
    persistence.save_findings(FINDINGS)
    persistence.save_traces(TRACES)
    persistence.save_jobs(SCAN_JOBS)
    return True


def get_policy(workspace_id: str) -> PolicyConfig:
    return workspaces_mod.store.get_policy(workspace_id)


def set_policy(workspace_id: str, policy: PolicyConfig) -> PolicyConfig:
    return workspaces_mod.store.set_policy(workspace_id, policy)


def add_finding(finding: Finding) -> Finding:
    FINDINGS[finding.id] = finding
    persistence.save_findings(FINDINGS)
    return finding


def list_findings(
    workspace_id: str | None = None,
    status: str | None = None,
) -> list[Finding]:
    rows = list(FINDINGS.values())
    if workspace_id:
        rows = [f for f in rows if f.workspace_id == workspace_id]
    if status:
        rows = [f for f in rows if f.status == status]
    rows.sort(key=lambda f: f.created_at, reverse=True)
    return rows


def patch_finding(finding_id: str, **updates: Any) -> Finding | None:
    item = FINDINGS.get(finding_id)
    if item is None:
        return None
    data = item.model_dump()
    data.update({k: v for k, v in updates.items() if v is not None})
    if updates.get("status") in ("fixed", "wontfix", "false_positive") and not data.get(
        "closed_at"
    ):
        data["closed_at"] = utc_now()
    updated = Finding.model_validate(data)
    FINDINGS[finding_id] = updated
    persistence.save_findings(FINDINGS)
    return updated


def add_trace(trace: Trace) -> Trace:
    TRACES[trace.id] = trace
    persistence.save_traces(TRACES)
    return trace


def list_traces(workspace_id: str | None = None) -> list[Trace]:
    rows = list(TRACES.values())
    if workspace_id:
        rows = [t for t in rows if t.workspace_id == workspace_id]
    rows.sort(key=lambda t: t.created_at, reverse=True)
    return rows


def add_job(job: ScanJob) -> ScanJob:
    SCAN_JOBS[job.id] = job
    persistence.save_jobs(SCAN_JOBS)
    return job


def put_job(job: ScanJob) -> ScanJob:
    """Update an existing job and flush to disk."""
    SCAN_JOBS[job.id] = job
    persistence.save_jobs(SCAN_JOBS)
    return job


def get_job(job_id: str) -> ScanJob | None:
    return SCAN_JOBS.get(job_id)


def gate_stats(workspace_id: str) -> dict[str, int]:
    open_findings = len(
        [f for f in FINDINGS.values() if f.workspace_id == workspace_id and f.status == "open"]
    )
    denies = 0
    for trace in TRACES.values():
        if trace.workspace_id != workspace_id:
            continue
        denies += sum(1 for e in trace.events if e.verdict == "deny")
    return {"open": open_findings, "denies": denies, "ci": denies}

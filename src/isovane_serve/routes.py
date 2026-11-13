"""Workspace catalog, Analyze / Watch / Fix APIs, and the release-gate decision."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from isovane_serve import store
from isovane_serve.diagram import analyze_code_workflow, analyze_diagram, analyze_upload_bytes
from isovane_serve.gate import judge
from isovane_serve.hunt import run_hunt
from isovane_serve.models import (
    Finding,
    FindingEvidence,
    ScanJob,
    SuggestedFix,
    Trace,
    TraceEvent,
    utc_now,
)
from isovane_serve.patches import accept_finding, mark_fixed, patch_for_finding
from isovane_serve.policy import policy_from_dict
from isovane_serve.remediations import finding_to_api_dict, hydrate_finding
from isovane_serve.repo import cleanup_temp, extract_archive, resolve_source
from isovane_serve.scan import analyze_workspace, to_sarif
from isovane_serve.simulate import run_pack
from isovane_serve.simulation_catalog import get_pack, list_packs, match_pack_for_finding

router = APIRouter()


class GateRequest(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    source: str = "user"
    confirmed: bool = False
    workspace_id: str | None = None
    agent_id: str | None = None
    run_id: str | None = None


class AnalyzeRequest(BaseModel):
    workspace_id: str
    folder: str | None = None
    repo: str | None = None
    prompts: list[str] = Field(default_factory=list)
    texts: list[dict[str, str]] = Field(default_factory=list)


class DiagramRequest(BaseModel):
    workspace_id: str
    mermaid: str | None = None
    description: str | None = None
    format: str | None = None
    content: str | None = None
    # Canonical Structurizr/C4 workspace — preferred when re-analyzing an edited board
    graph: dict | None = None
    # privacy = org→multi-cloud LLM residency; workflow = UI/agent/MCP graph; both = default
    mode: str = "both"
    folder: str | None = None  # optional: Agentic Radar–style inventory from source tree


class FindingPatch(BaseModel):
    status: str | None = None


class AgentRegister(BaseModel):
    prompts: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    mcp_servers: list[str] = Field(default_factory=list)
    model: str | None = None
    policy_id: str | None = None


class HuntRequest(BaseModel):
    workspace_id: str
    scenario_ids: list[str] | None = None


class SimulationRunRequest(BaseModel):
    inputs: dict[str, Any] = Field(default_factory=dict)
    finding_id: str | None = None


class WorkspaceCreate(BaseModel):
    name: str
    description: str | None = None
    folder: str | None = None
    stack: str | None = None
    branch: str = "main"
    icon: str | None = None


class WorkspaceUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    folder: str | None = None
    stack: str | None = None
    branch: str | None = None
    icon: str | None = None
    url: str | None = None


def _require_workspace(workspace_id: str) -> dict:
    item = store.workspace_by_id(workspace_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return item


@router.get("/workspaces")
def list_workspaces():
    return {"workspaces": store.list_workspaces(), "servers": store.SERVERS}


@router.post("/workspaces", status_code=201)
def create_workspace(body: WorkspaceCreate):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    return store.create_workspace(
        name,
        description=body.description,
        folder=body.folder,
        stack=body.stack,
        branch=body.branch,
        icon=body.icon,
    )


@router.get("/workspaces/{workspace_id}")
def get_workspace(workspace_id: str):
    item = _require_workspace(workspace_id)
    stats = store.gate_stats(workspace_id)
    return {**item, "gate": stats}


@router.get("/workspaces/{workspace_id}/board")
def get_workspace_board(workspace_id: str):
    """Return last Radar-class board persisted from code/diagram analyze."""
    _require_workspace(workspace_id)
    from isovane_serve.persistence import get_board

    board = get_board(workspace_id)
    if board is None:
        raise HTTPException(status_code=404, detail="No board saved for this workspace yet")
    return {"workspace_id": workspace_id, **board}


@router.patch("/workspaces/{workspace_id}")
def update_workspace(workspace_id: str, body: WorkspaceUpdate):
    _require_workspace(workspace_id)
    patch = body.model_dump(exclude_unset=True)
    if not patch:
        raise HTTPException(status_code=400, detail="No fields to update")
    if "name" in patch and not str(patch["name"] or "").strip():
        raise HTTPException(status_code=400, detail="Name is required")
    updated = store.update_workspace(workspace_id, patch)
    if updated is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return updated


@router.put("/workspaces/{workspace_id}")
def put_workspace(workspace_id: str, body: WorkspaceUpdate):
    return update_workspace(workspace_id, body)


@router.delete("/workspaces/{workspace_id}")
def delete_workspace(workspace_id: str):
    if not store.delete_workspace(workspace_id):
        raise HTTPException(status_code=404, detail="Workspace not found")
    return {"ok": True, "id": workspace_id}


@router.get("/workspaces/{workspace_id}/agents")
def list_agents(workspace_id: str):
    if store.workspace_by_id(workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return {"agents": store.AGENTS}


@router.put("/workspaces/{workspace_id}/agent")
def register_agent(workspace_id: str, body: AgentRegister):
    if store.workspace_by_id(workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    store.AGENT_REGISTRY[workspace_id] = body.model_dump()
    return {"workspace_id": workspace_id, "agent": body.model_dump()}


@router.get("/workspaces/{workspace_id}/services")
def list_services(workspace_id: str):
    if store.workspace_by_id(workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return {"services": store.SERVICES}


@router.get("/workspaces/{workspace_id}/logs")
def list_logs(workspace_id: str, source: str | None = None):
    if store.workspace_by_id(workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    rows = (
        store.LOGS
        if not source or source == "all"
        else [row for row in store.LOGS if row["source"] == source]
    )
    return {"logs": rows}


@router.get("/workspaces/{workspace_id}/policy")
def get_policy(workspace_id: str):
    if store.workspace_by_id(workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return store.get_policy(workspace_id).model_dump()


@router.put("/workspaces/{workspace_id}/policy")
def put_policy(workspace_id: str, body: dict[str, Any]):
    if store.workspace_by_id(workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    cfg = policy_from_dict(body)
    store.set_policy(workspace_id, cfg)
    return cfg.model_dump()


@router.post("/gates")
def decide_gate(body: GateRequest):
    workspace_id = body.workspace_id or "checkout-agent"
    policy = store.get_policy(workspace_id)
    decision = judge(body.model_dump(), policy)

    finding_id = None
    owasp = decision.get("owasp") or []
    pii_classes = decision.get("pii_classes") or []

    if decision["verdict"] == "deny":
        finding = Finding(
            workspace_id=workspace_id,
            agent_id=body.agent_id,
            source="watch",
            severity="high",
            title=f"Denied {body.tool}",
            summary=decision["reason"],
            owasp=owasp,
            category="runtime",
            evidence=FindingEvidence(
                tool=body.tool,
                args=body.args,
                source_channel=body.source,
                snippet=decision["reason"],
            ),
            pii_classes=pii_classes,
            policy_rule_id=decision.get("policy_rule_id"),
            suggested_fix=SuggestedFix(
                kind="policy",
                summary="Keep deny; tighten allow-list / confirm / PII rules.",
                diff=(
                    "# policies/default.yaml\n"
                    "block_if_untrusted_source: true\n"
                    "deny_pii_outbound: true\n"
                    f"require_confirm: [..., {body.tool}]\n"
                ),
                checklist=["Replay via Watch", "Add hunt regression"],
            ),
        )
        store.add_finding(finding)
        finding_id = finding.id

    event = TraceEvent(
        tool=body.tool,
        args=body.args,
        source=body.source,
        confirmed=body.confirmed,
        verdict=decision["verdict"],
        reason=decision["reason"],
        finding_id=finding_id,
        owasp=owasp,
        pii_classes=pii_classes,
    )
    trace = Trace(
        workspace_id=workspace_id,
        agent_id=body.agent_id,
        run_id=body.run_id,
        kind="watch",
        events=[event],
        finding_ids=[finding_id] if finding_id else [],
    )
    store.add_trace(trace)

    return {
        "tool": body.tool,
        "verdict": decision["verdict"],
        "reason": decision["reason"],
        "finding_id": finding_id,
        "trace_id": trace.id,
        "owasp": owasp,
        "pii_classes": pii_classes,
        "policy_rule_id": decision.get("policy_rule_id"),
    }


def _run_analyze_job(
    workspace_id: str,
    *,
    folder: str | None = None,
    repo: str | None = None,
    prompts: list[str] | None = None,
    texts: list[dict[str, str]] | None = None,
    archive: tuple[bytes, str] | None = None,
) -> dict:
    job = ScanJob(
        workspace_id=workspace_id,
        status="running",
        inputs={
            "folder": folder,
            "repo": repo,
            "prompts": prompts or [],
            "texts": texts or [],
            "archive": archive[1] if archive else None,
        },
    )
    store.add_job(job)
    temp_dir: str | None = None
    try:
        scan_folder = folder
        if archive is not None:
            path, temp_dir = extract_archive(archive[0], archive[1])
            scan_folder = str(path)
        elif repo or folder:
            path, temp_dir = resolve_source(folder=folder, repo=repo)
            scan_folder = str(path)
        findings = analyze_workspace(
            workspace_id,
            folder=scan_folder,
            prompts=prompts or [],
            text_blobs=texts or [],
        )
        for finding in findings:
            # Persist YAML remediations onto the finding so Details / Code Fix both see them.
            store.add_finding(hydrate_finding(finding))
        job.finding_ids = [f.id for f in findings]
        job.status = "done"
        job.finished_at = utc_now()
    except ValueError as exc:
        job.status = "failed"
        job.error = str(exc)
        job.finished_at = utc_now()
        store.put_job(job)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — surface in job
        job.status = "failed"
        job.error = str(exc)
        job.finished_at = utc_now()
    finally:
        cleanup_temp(temp_dir)
    store.put_job(job)
    return {
        "job": job.model_dump(),
        "findings": [
            finding_to_api_dict(store.FINDINGS[fid])
            for fid in job.finding_ids
            if fid in store.FINDINGS
        ],
    }


@router.post("/analyze")
def start_analyze(body: AnalyzeRequest):
    if store.workspace_by_id(body.workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return _run_analyze_job(
        body.workspace_id,
        folder=body.folder,
        repo=body.repo,
        prompts=body.prompts,
        texts=body.texts,
    )


@router.post("/analyze/archive")
async def analyze_archive(
    workspace_id: str = Form(...),
    file: UploadFile = File(...),
):
    if store.workspace_by_id(workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty archive")
    return _run_analyze_job(
        workspace_id,
        archive=(data, file.filename or "upload.zip"),
    )


def _normalize_arch_mode(raw: str | None) -> str:
    mode = (raw or "both").strip().lower()
    if mode in {"privacy", "cloud", "residency", "data"}:
        return "privacy"
    if mode in {"workflow", "agent", "graph", "mcp", "radar"}:
        return "workflow"
    return "both"


@router.post("/analyze/diagram")
async def analyze_diagram_route(
    workspace_id: str = Form(...),
    mermaid: str | None = Form(None),
    description: str | None = Form(None),
    format: str | None = Form(None),
    mode: str | None = Form("both"),
    folder: str | None = Form(None),
    file: UploadFile | None = File(None),
):
    if store.workspace_by_id(workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    arch_mode = _normalize_arch_mode(mode)  # type: ignore[arg-type]
    if folder:
        result = analyze_code_workflow(workspace_id, folder, mode=arch_mode)  # type: ignore[arg-type]
    elif file is not None:
        data = await file.read()
        result = analyze_upload_bytes(
            workspace_id,
            data,
            file.filename or "diagram",
            format_hint=format,
            mode=arch_mode,  # type: ignore[arg-type]
        )
    else:
        result = analyze_diagram(
            workspace_id,
            mermaid=mermaid,
            description=description,
            filename="diagram",
            format_hint=format,
            mode=arch_mode,  # type: ignore[arg-type]
        )
    findings = [hydrate_finding(f) for f in result["findings"]]
    for finding in findings:
        store.add_finding(finding)
    job = ScanJob(
        workspace_id=workspace_id,
        status="done",
        inputs={
            "diagram": True,
            "filename": file.filename if file else None,
            "format": format,
            "mode": arch_mode,
            "folder": folder,
        },
        finding_ids=[f.id for f in findings],
        finished_at=utc_now(),
    )
    store.add_job(job)
    return {
        "job": job.model_dump(),
        "findings": [f.model_dump() for f in findings],
        "inventory": result.get("inventory") or {},
        "mode": arch_mode,
    }


@router.post("/analyze/diagram/json")
def analyze_diagram_json(body: DiagramRequest):
    if store.workspace_by_id(body.workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    arch_mode = _normalize_arch_mode(body.mode)
    if body.folder:
        result = analyze_code_workflow(body.workspace_id, body.folder, mode=arch_mode)  # type: ignore[arg-type]
    else:
        content = body.content or body.description or body.mermaid
        result = analyze_diagram(
            body.workspace_id,
            mermaid=body.mermaid,
            description=content,
            filename=f"diagram.{body.format or 'txt'}",
            format_hint=body.format,
            mode=arch_mode,  # type: ignore[arg-type]
            graph=body.graph,
        )
    findings = [hydrate_finding(f) for f in result["findings"]]
    for finding in findings:
        store.add_finding(finding)
    return {
        "findings": [f.model_dump() for f in findings],
        "inventory": result.get("inventory") or {},
        "mode": arch_mode,
    }


@router.get("/analyze/{job_id}")
def get_analyze_job(job_id: str):
    job = store.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "job": job.model_dump(),
        "findings": [
            finding_to_api_dict(store.FINDINGS[fid])
            for fid in job.finding_ids
            if fid in store.FINDINGS
        ],
    }


@router.get("/findings")
def get_findings(
    workspace_id: str | None = None,
    status: str | None = None,
):
    rows = store.list_findings(workspace_id=workspace_id, status=status)
    # Hydrate on read so issue Details always show industry remediations,
    # even for findings created before remediations.yaml existed.
    hydrated = [hydrate_finding(f) for f in rows]
    for item in hydrated:
        store.FINDINGS[item.id] = item
    return {"findings": [f.model_dump() for f in hydrated]}


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str):
    item = store.FINDINGS.get(finding_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    hydrated = hydrate_finding(item)
    store.FINDINGS[finding_id] = hydrated
    return hydrated.model_dump()


@router.patch("/findings/{finding_id}")
def patch_finding_route(finding_id: str, body: FindingPatch):
    item = store.patch_finding(finding_id, status=body.status)
    if item is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding_to_api_dict(item)


@router.post("/hunt/run")
def hunt_run(body: HuntRequest):
    if store.workspace_by_id(body.workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return run_hunt(body.workspace_id, body.scenario_ids)


@router.get("/traces")
def get_traces(workspace_id: str | None = None):
    rows = store.list_traces(workspace_id)
    return {"traces": [t.model_dump() for t in rows]}


@router.get("/traces/{trace_id}")
def get_trace(trace_id: str):
    item = store.TRACES.get(trace_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Trace not found")
    return item.model_dump()


@router.post("/fixes/{finding_id}")
def create_fix(finding_id: str):
    patch = patch_for_finding(finding_id)
    if patch is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    accept_finding(finding_id)
    return patch


@router.post("/fixes/{finding_id}/done")
def complete_fix(finding_id: str):
    item = mark_fixed(finding_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return item.model_dump()


@router.get("/export/sarif")
def export_sarif(workspace_id: str = Query(...)):
    findings = store.list_findings(workspace_id=workspace_id, status="open")
    return to_sarif(findings)


@router.get("/gate/stats")
def gate_stats(workspace_id: str = Query(...)):
    if store.workspace_by_id(workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return store.gate_stats(workspace_id)


@router.get("/simulations")
def simulations_list():
    return {
        "banner": "Simulated lab — not your repository. No customer code is executed.",
        "packs": list_packs(),
    }


def _finding_blob(item: Finding) -> str:
    return " ".join(
        [
            item.title or "",
            item.summary or "",
            item.description or "",
            item.exploit or "",
            item.technical_details or "",
            item.category or "",
            " ".join(item.tags or []),
            " ".join(item.owasp or []),
            (item.evidence.snippet if item.evidence and item.evidence.snippet else "") or "",
            (item.evidence.tool if item.evidence and item.evidence.tool else "") or "",
            (item.evidence.path if item.evidence and item.evidence.path else "") or "",
        ]
    )


def _seed_inputs_from_finding(pack_id: str, item: Finding, inputs: dict[str, Any]) -> dict[str, Any]:
    """Prefill lab fields from evidence so the sim feels tied to this finding."""
    out = dict(inputs)
    snippet = ((item.evidence.snippet if item.evidence else None) or "").strip()
    path = (item.evidence.path if item.evidence else None) or ""
    blob = " ".join(
        [
            snippet,
            item.summary or "",
            item.exploit or "",
            item.technical_details or "",
        ]
    )
    seeded_from: list[str] = []

    if pack_id in {"prompt_injection", "prompt_leak"} and "system_prompt" not in out:
        source = snippet or (item.exploit or "").strip() or (item.summary or "").strip()
        if source:
            out["system_prompt"] = source[:2000]
            seeded_from.append("system_prompt")
        if pack_id == "prompt_injection" and "user_message" not in out and item.exploit:
            # Prefer a hostile user turn when exploit text looks like an injection
            exploit = item.exploit.strip()
            if any(k in exploit.lower() for k in ("ignore", "jailbreak", "override", "system")):
                out["user_message"] = exploit[:800]
                seeded_from.append("user_message")

    if pack_id == "ssrf_url" and "url" not in out:
        m = re.search(r"https?://[^\s'\"<>]+", blob)
        if m:
            out["url"] = m.group(0)
            seeded_from.append("url")
        elif any(k in blob.lower() for k in ("metadata", "169.254", "imds")):
            out["url"] = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            seeded_from.append("url")

    if pack_id == "shell_inject" and "command" not in out:
        if any(k in blob.lower() for k in ("shell", "subprocess", "os.system", "command")):
            out["command"] = "echo ok; cat secret.txt"
            seeded_from.append("command")

    if pack_id == "eval_exec" and "expression" not in out:
        m = re.search(r"eval\(([^)]+)\)", snippet)
        if m:
            out["expression"] = m.group(1).strip(" '\"")[:400]
            seeded_from.append("expression")
        elif "eval" in blob.lower() or "exec" in blob.lower():
            out["expression"] = '__import__("lab").os_system("whoami")'
            seeded_from.append("expression")

    if pack_id == "secret_leak":
        m = re.search(r"(sk-[\w-]+|AKIA[\w]+|ghp_[\w]+)", blob)
        if m and "grep" not in out:
            out["grep"] = m.group(0)[:12]
            seeded_from.append("grep")
        elif path:
            out.setdefault("grep", "sk-")
            seeded_from.append("grep")

    if pack_id == "rag_trust" and "public_doc" not in out and snippet:
        out["public_doc"] = snippet[:1200]
        seeded_from.append("public_doc")

    if pack_id == "pii_outbound" and "body" not in out:
        m = re.search(r"[A-Z]{5}\d{4}[A-Z]|ssn|aadhaar|\d{3}-\d{2}-\d{4}", blob, re.I)
        if m or "pii" in blob.lower():
            out["body"] = snippet[:500] if snippet else "PAN ABCDE1234F for wire"
            seeded_from.append("body")

    out["_finding_path"] = path
    out["_finding_title"] = item.title
    out["_seeded_fields"] = ",".join(seeded_from)
    return out


@router.get("/simulations/for-finding/{finding_id}")
def simulations_for_finding(finding_id: str):
    item = store.FINDINGS.get(finding_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    matched = match_pack_for_finding(_finding_blob(item), item.category)
    pack_id = matched["pack_id"]
    pack = get_pack(pack_id)
    seeded = _seed_inputs_from_finding(pack_id, item, {})
    seeded_fields = [
        f for f in str(seeded.get("_seeded_fields") or "").split(",") if f
    ]
    # Strip internal seed markers from client defaults
    client_defaults = {k: v for k, v in seeded.items() if not k.startswith("_")}
    return {
        "finding_id": finding_id,
        "pack_id": pack_id,
        "pack": pack,
        "seeded_inputs": client_defaults,
        "seeded_fields": seeded_fields,
        "confidence": matched["confidence"],
        "finding": {
            "id": item.id,
            "title": item.title,
            "severity": item.severity,
            "severity_label": item.severity_label,
            "category": item.category,
            "summary": item.summary,
            "path": item.evidence.path if item.evidence else None,
            "owasp": item.owasp,
        },
        "match_note": matched["match_note"],
    }


@router.get("/simulations/{pack_id}")
def simulations_get(pack_id: str):
    pack = get_pack(pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail="Simulation pack not found")
    return pack


@router.post("/simulations/{pack_id}/run")
def simulations_run(pack_id: str, body: SimulationRunRequest):
    if get_pack(pack_id) is None:
        raise HTTPException(status_code=404, detail="Simulation pack not found")
    inputs = dict(body.inputs or {})
    if body.finding_id:
        item = store.FINDINGS.get(body.finding_id)
        if item is not None:
            # Only fill keys the client left empty — preserve explicit edits
            seeded = _seed_inputs_from_finding(pack_id, item, {})
            for key, value in seeded.items():
                if key.startswith("_"):
                    continue
                if key not in inputs or inputs[key] in (None, ""):
                    inputs[key] = value
    try:
        return run_pack(pack_id, inputs)
    except KeyError:
        raise HTTPException(status_code=404, detail="Simulation pack not found") from None
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Simulation failed: {exc}") from exc

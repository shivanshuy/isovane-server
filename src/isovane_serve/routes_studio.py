"""Trust Studio APIs — toxic flows, dual-LLM, model-sees, patterns, trifecta."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from isovane_serve import store

router = APIRouter()


class GraphBody(BaseModel):
    graph: dict[str, Any] | None = None
    folder: str | None = None
    persist_findings: bool = True


class PatternApplyBody(BaseModel):
    pattern_id: str
    graph: dict[str, Any] | None = None


class ModelViewBody(BaseModel):
    folder: str | None = None
    live_probe: bool = False
    persist_findings: bool = True


def _require_workspace(workspace_id: str) -> dict:
    item = store.workspace_by_id(workspace_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return item


def _resolve_graph(workspace_id: str, graph: dict[str, Any] | None) -> dict[str, Any] | None:
    if graph:
        return graph
    from isovane_serve.persistence import get_board

    saved = get_board(workspace_id) or {}
    return saved.get("graph") or saved.get("board") or (saved if saved.get("nodes") else None)


def _resolve_folder(workspace_id: str, folder: str | None) -> str | None:
    if folder:
        return folder
    ws = store.workspace_by_id(workspace_id) or {}
    return str(ws.get("folder") or "") or None


@router.get("/trust-patterns")
def get_trust_patterns():
    from isovane_serve.trust_patterns import list_patterns

    return {"patterns": [p.model_dump(mode="json") for p in list_patterns()]}


@router.post("/workspaces/{workspace_id}/toxic-flows/analyze")
def post_toxic_flows_analyze(workspace_id: str, body: GraphBody | None = None):
    _require_workspace(workspace_id)
    body = body or GraphBody()
    from isovane_serve.toxic_flows import analyze_toxic_flows

    return analyze_toxic_flows(
        workspace_id,
        graph=_resolve_graph(workspace_id, body.graph),
        folder=_resolve_folder(workspace_id, body.folder),
        persist_findings=body.persist_findings,
    )


@router.get("/workspaces/{workspace_id}/toxic-flows")
def get_toxic_flows(workspace_id: str):
    _require_workspace(workspace_id)
    from isovane_serve.toxic_flows import last_toxic_flows

    last = last_toxic_flows(workspace_id)
    if last is None:
        raise HTTPException(status_code=404, detail="No toxic-flow analysis yet")
    return last


@router.post("/workspaces/{workspace_id}/dual-llm/lint")
def post_dual_llm_lint(workspace_id: str, body: GraphBody | None = None):
    _require_workspace(workspace_id)
    body = body or GraphBody()
    from isovane_serve.dual_llm_lint import lint_dual_llm

    return lint_dual_llm(
        workspace_id,
        _resolve_graph(workspace_id, body.graph),
        persist_findings=body.persist_findings,
    )


@router.post("/workspaces/{workspace_id}/dual-llm/apply")
def post_dual_llm_apply(workspace_id: str, body: GraphBody | None = None):
    _require_workspace(workspace_id)
    body = body or GraphBody()
    from isovane_serve.dual_llm_rewrite import apply_dual_llm

    result = apply_dual_llm(workspace_id, body.graph)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or "Apply failed")
    return result


@router.post("/workspaces/{workspace_id}/mcp/model-view")
def post_mcp_model_view(workspace_id: str, body: ModelViewBody | None = None):
    _require_workspace(workspace_id)
    body = body or ModelViewBody()
    from isovane_serve.mcp_model_view import analyze_model_views

    folder = _resolve_folder(workspace_id, body.folder)
    if not folder:
        raise HTTPException(status_code=400, detail="Workspace folder required for model-view")
    return analyze_model_views(
        workspace_id,
        folder,
        live_probe=body.live_probe,
        persist_findings=body.persist_findings,
    )


@router.post("/workspaces/{workspace_id}/board/apply-pattern")
def post_apply_pattern(workspace_id: str, body: PatternApplyBody):
    _require_workspace(workspace_id)
    from isovane_serve.trust_patterns import apply_pattern

    result = apply_pattern(workspace_id, body.pattern_id, body.graph)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or "Apply failed")
    return result


@router.get("/workspaces/{workspace_id}/scorecard/trifecta")
@router.post("/workspaces/{workspace_id}/scorecard/trifecta")
def scorecard_trifecta(workspace_id: str, body: GraphBody | None = None):
    _require_workspace(workspace_id)
    body = body or GraphBody()
    from isovane_serve.trifecta import score_trifecta

    return score_trifecta(
        workspace_id,
        graph=_resolve_graph(workspace_id, body.graph),
    )


@router.get("/workspaces/{workspace_id}/studio")
def get_studio_state(workspace_id: str):
    _require_workspace(workspace_id)
    from isovane_serve.persistence import get_studio

    return {"workspace_id": workspace_id, **(get_studio(workspace_id) or {})}

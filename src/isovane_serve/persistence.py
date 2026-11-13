"""Durable findings, traces, scan jobs, and policies under ISOVANE_DATA_DIR."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from isovane_serve.models import Finding, PolicyConfig, ScanJob, Trace
from isovane_serve.workspaces import data_dir

_LOCK = threading.RLock()


def findings_path() -> Path:
    return data_dir() / "findings.json"


def traces_path() -> Path:
    return data_dir() / "traces.json"


def jobs_path() -> Path:
    return data_dir() / "scan_jobs.json"


def policies_path() -> Path:
    return data_dir() / "policies.json"


def boards_path() -> Path:
    return data_dir() / "boards.json"


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_findings() -> dict[str, Finding]:
    raw = _read_json(findings_path())
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Finding] = {}
    for fid, row in raw.items():
        try:
            out[str(fid)] = Finding.model_validate(row)
        except Exception:  # noqa: BLE001
            continue
    return out


def save_findings(findings: dict[str, Finding]) -> None:
    with _LOCK:
        payload = {fid: f.model_dump(mode="json") for fid, f in findings.items()}
        _write_json(findings_path(), payload)


def load_traces() -> dict[str, Trace]:
    raw = _read_json(traces_path())
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Trace] = {}
    for tid, row in raw.items():
        try:
            out[str(tid)] = Trace.model_validate(row)
        except Exception:  # noqa: BLE001
            continue
    return out


def save_traces(traces: dict[str, Trace]) -> None:
    with _LOCK:
        payload = {tid: t.model_dump(mode="json") for tid, t in traces.items()}
        _write_json(traces_path(), payload)


def load_jobs() -> dict[str, ScanJob]:
    raw = _read_json(jobs_path())
    if not isinstance(raw, dict):
        return {}
    out: dict[str, ScanJob] = {}
    for jid, row in raw.items():
        try:
            out[str(jid)] = ScanJob.model_validate(row)
        except Exception:  # noqa: BLE001
            continue
    return out


def save_jobs(jobs: dict[str, ScanJob]) -> None:
    with _LOCK:
        payload = {jid: j.model_dump(mode="json") for jid, j in jobs.items()}
        _write_json(jobs_path(), payload)


def load_policies() -> dict[str, PolicyConfig]:
    raw = _read_json(policies_path())
    if not isinstance(raw, dict):
        return {}
    out: dict[str, PolicyConfig] = {}
    for wid, row in raw.items():
        try:
            out[str(wid)] = PolicyConfig.model_validate(row)
        except Exception:  # noqa: BLE001
            continue
    return out


def save_policies(policies: dict[str, Any]) -> None:
    with _LOCK:
        payload: dict[str, Any] = {}
        for wid, pol in policies.items():
            if hasattr(pol, "model_dump"):
                payload[str(wid)] = pol.model_dump(mode="json")
            elif isinstance(pol, dict):
                payload[str(wid)] = pol
        _write_json(policies_path(), payload)


def load_boards() -> dict[str, Any]:
    raw = _read_json(boards_path())
    return raw if isinstance(raw, dict) else {}


def save_board(workspace_id: str, board: dict[str, Any]) -> None:
    with _LOCK:
        all_boards = load_boards()
        all_boards[str(workspace_id)] = board
        _write_json(boards_path(), all_boards)


def get_board(workspace_id: str) -> dict[str, Any] | None:
    board = load_boards().get(str(workspace_id))
    return board if isinstance(board, dict) else None


def delete_workspace_artifacts(workspace_id: str) -> None:
    """Drop persisted findings/traces/jobs/board for a deleted workspace."""
    with _LOCK:
        findings = load_findings()
        findings = {k: v for k, v in findings.items() if v.workspace_id != workspace_id}
        save_findings(findings)
        traces = load_traces()
        traces = {k: v for k, v in traces.items() if v.workspace_id != workspace_id}
        save_traces(traces)
        jobs = load_jobs()
        jobs = {
            k: v
            for k, v in jobs.items()
            if getattr(v, "workspace_id", None) != workspace_id
        }
        save_jobs(jobs)
        boards = load_boards()
        if workspace_id in boards:
            boards.pop(workspace_id, None)
            _write_json(boards_path(), boards)
        policies = load_policies()
        if workspace_id in policies:
            policies.pop(workspace_id, None)
            save_policies(policies)

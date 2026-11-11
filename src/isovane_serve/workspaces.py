"""Persistent workspace catalog: list / create / get / update / delete."""

from __future__ import annotations

import json
import os
import threading
from copy import deepcopy
from pathlib import Path
from typing import Any

from isovane_serve.policy import load_policy

_LOCK = threading.RLock()

_DEFAULTS: list[dict[str, Any]] = [
    {
        "id": "checkout-agent",
        "name": "checkout-agent",
        "description": "Checkout and refund agent under policy gate.",
        "folder": "~/agents/checkout-agent",
        "stack": "LangGraph · Python",
        "branch": "main",
        "icon": "drop",
        "url": "checkout-agent.localhost",
        "uptime": "42 m",
        "since": "10:14",
        "cpu": 12,
        "cpuPeak": "Peak 38% · 5 min",
        "memory": "412 MB",
        "memoryOf": "of 48 GB",
        "energy": "3.1 W",
        "energyNote": "Low · average",
        "ports": [
            {"label": "gate", "port": "8092"},
            {"label": "agent", "port": "2026"},
        ],
    },
    {
        "id": "support-bot",
        "name": "support-bot",
        "description": "Customer support bot with tool egress controls.",
        "folder": "~/agents/support-bot",
        "stack": "LangChain · TS",
        "branch": "main",
        "icon": "n",
        "url": "support-bot.localhost",
        "uptime": "3 h",
        "since": "07:02",
        "cpu": 6,
        "cpuPeak": "Peak 22% · 5 min",
        "memory": "188 MB",
        "memoryOf": "of 48 GB",
        "energy": "1.4 W",
        "energyNote": "Low · average",
        "ports": [{"label": "tools", "port": "4000"}],
    },
    {
        "id": "ops-runner",
        "name": "ops-runner",
        "description": "Ops MCP runner for privileged tooling.",
        "folder": "~/agents/ops-runner",
        "stack": "MCP · Python",
        "branch": "secure",
        "icon": "bolt",
        "url": "ops-runner.localhost",
        "uptime": "18 m",
        "since": "10:38",
        "cpu": 21,
        "cpuPeak": "Peak 44% · 5 min",
        "memory": "640 MB",
        "memoryOf": "of 48 GB",
        "energy": "4.6 W",
        "energyNote": "Low · average",
        "ports": [{"label": "mcp", "port": "3100"}],
    },
    {
        "id": "research-agent",
        "name": "research-agent",
        "description": "Research agent with browsing and synthesis tools.",
        "folder": "~/agents/research-agent",
        "stack": "OpenAI tools",
        "branch": "main",
        "icon": "s",
        "url": "research-agent.localhost",
        "uptime": "1 h",
        "since": "09:20",
        "cpu": 4,
        "cpuPeak": "Peak 11% · 5 min",
        "memory": "96 MB",
        "memoryOf": "of 48 GB",
        "energy": "0.8 W",
        "energyNote": "Low · average",
        "ports": [{"label": "api", "port": "8080"}],
    },
]

_EDITABLE = {
    "name",
    "description",
    "folder",
    "stack",
    "branch",
    "icon",
    "url",
}


def data_dir() -> Path:
    raw = os.environ.get("ISOVANE_DATA_DIR")
    if raw:
        path = Path(raw).expanduser()
    else:
        path = Path(__file__).resolve().parents[2] / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def workspaces_path() -> Path:
    return data_dir() / "workspaces.json"


def _normalize(item: dict[str, Any]) -> dict[str, Any]:
    wid = str(item.get("id") or "").strip()
    name = str(item.get("name") or wid).strip() or wid
    return {
        "id": wid,
        "name": name,
        "description": str(item.get("description") or "").strip(),
        "folder": str(item.get("folder") or f"~/agents/{wid}"),
        "stack": str(item.get("stack") or "Agent"),
        "branch": str(item.get("branch") or "main"),
        "icon": str(item.get("icon") or "drop"),
        "url": str(item.get("url") or f"{wid}.localhost"),
        "uptime": str(item.get("uptime") or "—"),
        "since": str(item.get("since") or "—"),
        "cpu": int(item.get("cpu") or 0),
        "cpuPeak": str(item.get("cpuPeak") or "—"),
        "memory": str(item.get("memory") or "—"),
        "memoryOf": str(item.get("memoryOf") or ""),
        "energy": str(item.get("energy") or "—"),
        "energyNote": str(item.get("energyNote") or ""),
        "ports": list(item.get("ports") or []),
    }


def _slug(name: str) -> str:
    raw = "".join(ch.lower() if ch.isalnum() else "-" for ch in name.strip())
    while "--" in raw:
        raw = raw.replace("--", "-")
    return raw.strip("-") or "workspace"


class WorkspaceStore:
    def __init__(self) -> None:
        self._items: list[dict[str, Any]] = []
        self._policies: dict[str, Any] = {}
        self.reload()

    def reload(self) -> None:
        with _LOCK:
            path = workspaces_path()
            if path.exists():
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    rows = payload.get("workspaces", payload if isinstance(payload, list) else [])
                    self._items = [_normalize(row) for row in rows if row.get("id")]
                except (OSError, json.JSONDecodeError, TypeError, ValueError):
                    self._items = [_normalize(row) for row in deepcopy(_DEFAULTS)]
                    self._persist_unlocked()
            else:
                self._items = [_normalize(row) for row in deepcopy(_DEFAULTS)]
                self._persist_unlocked()
            for item in self._items:
                self._policies.setdefault(item["id"], load_policy())

    def _persist_unlocked(self) -> None:
        path = workspaces_path()
        path.write_text(
            json.dumps({"workspaces": self._items}, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def list(self) -> list[dict[str, Any]]:
        with _LOCK:
            return deepcopy(self._items)

    def get(self, workspace_id: str) -> dict[str, Any] | None:
        with _LOCK:
            for item in self._items:
                if item["id"] == workspace_id:
                    return deepcopy(item)
            return None

    def create(
        self,
        name: str,
        *,
        description: str | None = None,
        folder: str | None = None,
        stack: str | None = None,
        branch: str = "main",
        icon: str | None = None,
    ) -> dict[str, Any]:
        with _LOCK:
            base = _slug(name)
            wid = base
            n = 2
            existing = {item["id"] for item in self._items}
            while wid in existing:
                wid = f"{base}-{n}"
                n += 1
            icons = ["drop", "n", "bolt", "s"]
            item = _normalize(
                {
                    "id": wid,
                    "name": name.strip() or wid,
                    "description": description or "",
                    "folder": folder or f"~/agents/{wid}",
                    "stack": stack or "Agent",
                    "branch": branch,
                    "icon": icon or icons[len(self._items) % len(icons)],
                    "url": f"{wid}.localhost",
                }
            )
            self._items.append(item)
            self._policies[wid] = load_policy()
            self._persist_unlocked()
            return deepcopy(item)

    def update(self, workspace_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
        with _LOCK:
            for index, item in enumerate(self._items):
                if item["id"] != workspace_id:
                    continue
                updated = dict(item)
                for key, value in patch.items():
                    if key not in _EDITABLE or value is None:
                        continue
                    if isinstance(value, str):
                        updated[key] = value.strip()
                    else:
                        updated[key] = value
                if not updated.get("name"):
                    updated["name"] = workspace_id
                normalized = _normalize(updated)
                self._items[index] = normalized
                self._persist_unlocked()
                return deepcopy(normalized)
            return None

    def delete(self, workspace_id: str) -> bool:
        with _LOCK:
            before = len(self._items)
            self._items = [item for item in self._items if item["id"] != workspace_id]
            if len(self._items) == before:
                return False
            self._policies.pop(workspace_id, None)
            self._persist_unlocked()
            return True

    def get_policy(self, workspace_id: str) -> Any:
        with _LOCK:
            return self._policies.get(workspace_id) or load_policy()

    def set_policy(self, workspace_id: str, policy: Any) -> Any:
        with _LOCK:
            self._policies[workspace_id] = policy
            return policy


store = WorkspaceStore()

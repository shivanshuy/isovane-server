"""Minimal Python sidecar: wrap tool invoke with POST /gates."""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Callable


def gated_tool(
    tool: str,
    args: dict[str, Any],
    *,
    source: str = "user",
    confirmed: bool = False,
    workspace_id: str = "checkout-agent",
    base_url: str = "http://127.0.0.1:8092",
    invoke: Callable[[dict[str, Any]], Any] | None = None,
) -> Any:
    body = {
        "tool": tool,
        "args": args,
        "source": source,
        "confirmed": confirmed,
        "workspace_id": workspace_id,
    }
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/gates",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        decision = json.loads(resp.read().decode("utf-8"))
    if decision.get("verdict") != "allow":
        raise PermissionError(
            f"DENY {tool}: {decision.get('reason')} "
            f"(finding={decision.get('finding_id')})"
        )
    if invoke is None:
        return decision
    return invoke(args)


if __name__ == "__main__":
    try:
        gated_tool("send", {"to": "a@b.com"}, source="email", confirmed=True)
    except PermissionError as exc:
        print(exc)

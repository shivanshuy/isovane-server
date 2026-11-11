#!/usr/bin/env python3
"""CI gate: fail when hunt regressions or open high/critical findings exist.

Usage:
  python scripts/ci_gate.py --workspace checkout-agent
  python scripts/ci_gate.py --base-url http://127.0.0.1:8092 --workspace checkout-agent
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


def _post(base: str, path: str, body: dict) -> dict:
    req = urllib.request.Request(
        f"{base.rstrip('/')}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get(base: str, path: str) -> dict:
    with urllib.request.urlopen(f"{base.rstrip('/')}{path}", timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Isovane CI gate")
    parser.add_argument("--base-url", default="http://127.0.0.1:8092")
    parser.add_argument("--workspace", default="checkout-agent")
    parser.add_argument("--skip-hunt", action="store_true")
    args = parser.parse_args()

    failures: list[str] = []

    if not args.skip_hunt:
        hunt = _post(args.base_url, "/hunt/run", {"workspace_id": args.workspace})
        if not hunt.get("ok"):
            failures.append(f"hunt regressions: {hunt.get('regressions')}")

    findings = _get(
        args.base_url, f"/findings?workspace_id={args.workspace}&status=open"
    ).get("findings", [])
    hot = [f for f in findings if f.get("severity") in ("critical", "high")]
    if hot:
        failures.append(f"{len(hot)} open high/critical findings")

    if failures:
        print("ISOVANE CI GATE: FAIL")
        for item in failures:
            print(f" - {item}")
        return 1

    print("ISOVANE CI GATE: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.URLError as exc:
        print(f"ISOVANE CI GATE: ERROR contacting server ({exc})")
        raise SystemExit(2) from exc

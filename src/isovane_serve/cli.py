"""CI-facing CLI: isovane-scan PATH [--sarif] [--fail-on SEVERITY]."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from isovane_serve.scan import analyze_workspace, to_sarif

_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="isovane-scan",
        description="Isovane agent/LLM static scan (Semgrep compose + Bandit + promptlint).",
    )
    parser.add_argument("path", nargs="?", default=".", help="Folder to scan")
    parser.add_argument(
        "--sarif",
        metavar="FILE",
        help="Write SARIF 2.1 to FILE (use - for stdout)",
    )
    parser.add_argument(
        "--json",
        dest="json_out",
        metavar="FILE",
        help="Write findings JSON to FILE (use - for stdout)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical"),
        default="high",
        help="Exit 1 if any open finding at this severity or above (default: high)",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Always exit 0 (still print summary)",
    )
    parser.add_argument(
        "--workspace-id",
        default="cli",
        help="Workspace id stamped on findings",
    )
    args = parser.parse_args(argv)

    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(f"isovane-scan: path not found: {root}", file=sys.stderr)
        return 2

    findings = analyze_workspace(args.workspace_id, folder=str(root))
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    print(
        f"isovane-scan: {len(findings)} findings in {root}"
        + (f" ({', '.join(f'{k}={v}' for k, v in sorted(by_sev.items(), key=lambda x: -_RANK.get(x[0], 0)))})" if by_sev else "")
    )
    for f in findings[:30]:
        loc = f.evidence.path or "?"
        line = f":{f.evidence.line}" if f.evidence.line else ""
        print(f"  [{f.severity}] {f.title} — {loc}{line}")
    if len(findings) > 30:
        print(f"  … {len(findings) - 30} more")

    if args.sarif:
        payload = to_sarif(findings)
        _write(args.sarif, json.dumps(payload, indent=2))
    if args.json_out:
        payload = [f.model_dump() for f in findings]
        _write(args.json_out, json.dumps(payload, indent=2))

    if args.no_fail:
        return 0
    threshold = _RANK[args.fail_on]
    if any(_RANK.get(f.severity, 0) >= threshold for f in findings):
        return 1
    return 0


def _write(target: str, text: str) -> None:
    if target == "-":
        print(text)
        return
    Path(target).write_text(text, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Side-by-side bake-off: Isovane vs LLMArmor (when installed).

Method is documented in tests/bakeoff/COMPARISON.md.

Usage (from isovane-server):
  poetry run python scripts/bakeoff_compare_llmarmor.py
  poetry run python scripts/bakeoff_compare_llmarmor.py --install-hint
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from isovane_serve.scan import analyze_workspace  # noqa: E402


def _expected_map() -> dict[str, dict]:
    expected_dir = ROOT / "tests" / "bakeoff" / "expected"
    out: dict[str, dict] = {}
    for path in sorted(expected_dir.glob("*.json")):
        out[path.stem] = json.loads(path.read_text(encoding="utf-8"))
    return out


def _recall(blob: str, substrings: list[str]) -> tuple[float | None, list[str]]:
    if not substrings:
        return None, []
    hits = [s for s in substrings if s.lower() in blob.lower()]
    return len(hits) / len(substrings), hits


def score_isovane(fixture: Path, expected: dict) -> dict:
    findings = analyze_workspace("bakeoff-compare", folder=str(fixture))
    titles = [f.title for f in findings]
    blob = " ".join(titles)
    subs = [str(s) for s in expected.get("must_match_substrings") or []]
    recall, hits = _recall(blob, subs)
    return {
        "engine": "isovane",
        "findings": len(findings),
        "titles": titles[:20],
        "finding_recall": None if recall is None else round(recall, 3),
        "substring_hits": hits,
    }


def _find_llmarmor() -> list[str] | None:
    exe = shutil.which("llmarmor")
    if exe:
        return [exe]
    # module form
    try:
        import llmarmor  # noqa: F401
    except ImportError:
        return None
    return [sys.executable, "-m", "llmarmor"]


def _run_llmarmor(cmd: list[str], fixture: Path) -> tuple[str, str]:
    """Return (stdout, stderr). Try common CLIs."""
    attempts = [
        cmd + ["scan", str(fixture)],
        cmd + [str(fixture)],
        cmd + ["--path", str(fixture)],
    ]
    last_err = ""
    for args in attempts:
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(ROOT),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            last_err = str(exc)
            continue
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode in (0, 1, 2) and out.strip():
            return out, ""
        last_err = out or f"exit {proc.returncode}"
    return "", last_err


def score_llmarmor(fixture: Path, expected: dict, cmd: list[str]) -> dict:
    stdout, err = _run_llmarmor(cmd, fixture)
    if not stdout and err:
        return {
            "engine": "llmarmor",
            "available": True,
            "error": err[:400],
            "finding_recall": None,
            "substring_hits": [],
        }
    # Prefer titles/messages; fall back to full output for substring recall
    lines = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Common patterns: "TITLE: ..." or SARIF-ish or "[HIGH] ..."
        m = re.match(r"^\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+)$", line, re.I)
        if m:
            lines.append(m.group(1))
            continue
        if re.search(r"LLM0\d|prompt|shell|secret|agency|injection", line, re.I):
            lines.append(line)
    blob = "\n".join(lines) if lines else stdout
    subs = [str(s) for s in expected.get("must_match_substrings") or []]
    recall, hits = _recall(blob, subs)
    return {
        "engine": "llmarmor",
        "available": True,
        "findings_est": len(lines) or (1 if stdout.strip() else 0),
        "sample": (stdout[:600] + ("…" if len(stdout) > 600 else "")),
        "finding_recall": None if recall is None else round(recall, 3),
        "substring_hits": hits,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--install-hint",
        action="store_true",
        help="Print install hint for llmarmor and exit",
    )
    args = parser.parse_args()
    if args.install_hint:
        print("pip install llmarmor  # or: pipx install llmarmor")
        print("Then re-run: poetry run python scripts/bakeoff_compare_llmarmor.py")
        return 0

    fixtures_root = ROOT / "tests" / "bakeoff" / "fixtures"
    expected = _expected_map()
    llm_cmd = _find_llmarmor()

    rows = []
    for fixture in sorted(p for p in fixtures_root.iterdir() if p.is_dir()):
        exp = expected.get(fixture.name)
        if not exp:
            continue
        # Skip inventory-only fixtures for engine substring compare fairness note
        iso = score_isovane(fixture, exp)
        row: dict = {
            "fixture": fixture.name,
            "must_match_substrings": exp.get("must_match_substrings") or [],
            "isovane": iso,
        }
        if llm_cmd:
            row["llmarmor"] = score_llmarmor(fixture, exp, llm_cmd)
        else:
            row["llmarmor"] = {
                "engine": "llmarmor",
                "available": False,
                "finding_recall": None,
                "note": "not installed — Isovane scores still recorded",
            }
        rows.append(row)
        iso_r = iso.get("finding_recall")
        llm = row["llmarmor"]
        llm_r = llm.get("finding_recall")
        print(
            f"{fixture.name}: isovane_recall={iso_r} "
            f"llmarmor_recall={llm_r} llmarmor_available={llm.get('available')}"
        )

    out = {
        "method": "tests/bakeoff/COMPARISON.md",
        "llmarmor_available": bool(llm_cmd),
        "fixtures": rows,
    }
    path = ROOT / "tests" / "bakeoff" / "last_compare.json"
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Wrote {path}")
    if not llm_cmd:
        print(
            "NOTE: LLMArmor not installed; published method still valid. "
            "Install with: pip install llmarmor"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

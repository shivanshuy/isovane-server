#!/usr/bin/env python3
"""Score Isovane analyze (+ optional inventory) against bake-off expected hints.

Usage (from isovane-server):
  poetry run python scripts/bakeoff_score.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from isovane_serve.scan import analyze_workspace  # noqa: E402
from isovane_serve.workflow_inventory import inventory_from_tree  # noqa: E402


def score_fixture(fixture: Path, expected: dict) -> dict:
    findings = analyze_workspace("bakeoff", folder=str(fixture))
    titles = [f.title for f in findings]
    blob = " ".join(titles).lower()

    substrings = [s.lower() for s in expected.get("must_match_substrings") or []]
    hit_subs = [s for s in substrings if s in blob]
    finding_recall = (len(hit_subs) / len(substrings)) if substrings else None

    inv_ok = True
    inv_detail: dict = {}
    need_labels = expected.get("inventory_must_have_labels") or []
    need_kinds = expected.get("inventory_must_have_edge_kinds") or []
    if need_labels or need_kinds:
        inv = inventory_from_tree(fixture)
        labels = {str(n.get("label")) for n in inv.get("nodes") or []}
        kinds = {str(e.get("kind")) for e in inv.get("edges") or []}
        missing_labels = [x for x in need_labels if x not in labels]
        missing_kinds = [x for x in need_kinds if x not in kinds]
        inv_ok = not missing_labels and not missing_kinds
        inv_detail = {
            "labels": sorted(labels),
            "edge_kinds": sorted(kinds),
            "missing_labels": missing_labels,
            "missing_kinds": missing_kinds,
        }

    # Combined recall: average of finding recall (if any) and inventory pass (1/0)
    parts: list[float] = []
    if finding_recall is not None:
        parts.append(finding_recall)
    if need_labels or need_kinds:
        parts.append(1.0 if inv_ok else 0.0)
    recall = sum(parts) / len(parts) if parts else 0.0

    return {
        "fixture": fixture.name,
        "findings": len(findings),
        "titles": titles[:16],
        "substring_hits": hit_subs,
        "finding_recall": finding_recall,
        "inventory_ok": inv_ok if (need_labels or need_kinds) else None,
        "inventory": inv_detail or None,
        "recall": round(recall, 3),
    }


def main() -> int:
    fixtures = ROOT / "tests" / "bakeoff" / "fixtures"
    expected_dir = ROOT / "tests" / "bakeoff" / "expected"
    if not fixtures.exists():
        print("No fixtures directory")
        return 1

    rows = []
    for fixture in sorted(p for p in fixtures.iterdir() if p.is_dir()):
        exp_path = expected_dir / f"{fixture.name}.json"
        if not exp_path.exists():
            print(f"SKIP {fixture.name}: no expected file")
            continue
        expected = json.loads(exp_path.read_text(encoding="utf-8"))
        row = score_fixture(fixture, expected)
        rows.append(row)
        print(
            f"{fixture.name}: findings={row['findings']} recall={row['recall']:.2f} "
            f"hits={row['substring_hits']} inv_ok={row['inventory_ok']}"
        )

    out = ROOT / "tests" / "bakeoff" / "last_score.json"
    out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"Wrote {out}")
    print(f"fixtures_scored={len(rows)}")
    if len(rows) < 5:
        print("FAIL: need ≥5 scored fixtures")
        return 1
    if not all(r["recall"] >= 0.5 for r in rows):
        print("FAIL: recall < 0.5 on one or more fixtures")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

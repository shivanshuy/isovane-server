"""F1: bake-off corpus size + minimum recall."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "bakeoff" / "fixtures"
EXPECTED = ROOT / "tests" / "bakeoff" / "expected"


def _load_score_mod():
    path = ROOT / "scripts" / "bakeoff_score.py"
    spec = importlib.util.spec_from_file_location("bakeoff_score", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_bakeoff_has_at_least_five_fixtures():
    dirs = [p for p in FIXTURES.iterdir() if p.is_dir()]
    assert len(dirs) >= 5, f"need ≥5 fixtures, got {[p.name for p in dirs]}"
    for d in dirs:
        assert (EXPECTED / f"{d.name}.json").is_file(), f"missing expected for {d.name}"


def test_bakeoff_each_fixture_recall_at_least_half():
    mod = _load_score_mod()
    rows = []
    for fixture in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        expected = json.loads((EXPECTED / f"{fixture.name}.json").read_text(encoding="utf-8"))
        row = mod.score_fixture(fixture, expected)
        rows.append(row)
        assert row["recall"] >= 0.5, row
    assert len(rows) >= 5

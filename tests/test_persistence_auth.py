"""Durable findings + optional API key auth."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from isovane_serve import store
from isovane_serve import workspaces as ws
from isovane_serve.main import app
from isovane_serve.models import Finding, FindingEvidence


def test_findings_survive_rebootstrap(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ISOVANE_DATA_DIR", str(tmp_path))
    ws.store = ws.WorkspaceStore()
    store.FINDINGS.clear()
    store.bootstrap_persistence()

    finding = Finding(
        workspace_id="checkout-agent",
        source="analyze",
        severity="medium",
        title="Durable test finding",
        summary="persisted",
        category="static",
        evidence=FindingEvidence(path="a.py", tool="test"),
    )
    store.add_finding(finding)
    assert (tmp_path / "findings.json").exists()

    store.FINDINGS.clear()
    store.bootstrap_persistence()
    assert finding.id in store.FINDINGS
    assert store.FINDINGS[finding.id].title == "Durable test finding"


def test_api_key_required_when_configured(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ISOVANE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ISOVANE_API_KEY", "secret-test-key")
    ws.store = ws.WorkspaceStore()
    client = TestClient(app)

    assert client.get("/health").status_code == 200
    denied = client.get("/workspaces")
    assert denied.status_code == 401

    ok = client.get("/workspaces", headers={"X-Api-Key": "secret-test-key"})
    assert ok.status_code == 200
    assert "workspaces" in ok.json()


def test_api_key_bearer_accepted(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ISOVANE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ISOVANE_API_KEY", "secret-test-key")
    client = TestClient(app)
    ok = client.get("/workspaces", headers={"Authorization": "Bearer secret-test-key"})
    assert ok.status_code == 200

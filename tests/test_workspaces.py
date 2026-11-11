from pathlib import Path

from fastapi.testclient import TestClient

from isovane_serve import workspaces as ws
from isovane_serve.main import app


def test_workspace_crud(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ISOVANE_DATA_DIR", str(tmp_path))
    ws.store = ws.WorkspaceStore()

    client = TestClient(app)

    listed = client.get("/workspaces")
    assert listed.status_code == 200
    assert len(listed.json()["workspaces"]) == 4

    created = client.post(
        "/workspaces",
        json={"name": "Billing Bot", "description": "Invoice agent"},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["id"] == "billing-bot"
    assert body["description"] == "Invoice agent"
    assert (tmp_path / "workspaces.json").exists()

    got = client.get(f"/workspaces/{body['id']}")
    assert got.status_code == 200
    assert got.json()["name"] == "Billing Bot"
    assert "gate" in got.json()

    updated = client.patch(
        f"/workspaces/{body['id']}",
        json={"description": "Updated invoice agent", "stack": "LangGraph"},
    )
    assert updated.status_code == 200
    assert updated.json()["description"] == "Updated invoice agent"
    assert updated.json()["stack"] == "LangGraph"

    missing = client.get("/workspaces/does-not-exist")
    assert missing.status_code == 404
    assert missing.json()["detail"] == "Workspace not found"

    deleted = client.delete(f"/workspaces/{body['id']}")
    assert deleted.status_code == 200
    assert client.get(f"/workspaces/{body['id']}").status_code == 404


def test_create_requires_name(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ISOVANE_DATA_DIR", str(tmp_path))
    ws.store = ws.WorkspaceStore()
    client = TestClient(app)
    response = client.post("/workspaces", json={"name": "   "})
    assert response.status_code == 400

from fastapi.testclient import TestClient

from isovane_serve import store
from isovane_serve import workspaces as ws_mod
from isovane_serve.main import app


def test_trust_patterns_and_trifecta_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("ISOVANE_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("ISOVANE_API_KEY", raising=False)
    ws_mod.store = ws_mod.WorkspaceStore()
    store.FINDINGS.clear()
    store.bootstrap_persistence()
    client = TestClient(app)
    ws = client.post("/workspaces", json={"name": "Studio WS"}).json()
    wid = ws["id"]

    patterns = client.get("/trust-patterns").json()
    assert patterns["patterns"]

    board = {
        "nodes": [
            {"id": "ui", "label": "Chat UI", "kind": "ui"},
            {"id": "agent", "label": "Agent", "kind": "agent"},
            {"id": "data", "label": "CRM", "kind": "data"},
            {"id": "mail", "label": "send_email", "kind": "tool"},
        ],
        "edges": [
            {"from": "ui", "to": "agent", "kind": "prompt"},
            {"from": "data", "to": "agent", "kind": "read"},
            {"from": "agent", "to": "mail", "kind": "tool"},
        ],
    }
    put = client.put(f"/workspaces/{wid}/board", json={"board": board, "source": "test"})
    assert put.status_code == 200

    toxic = client.post(f"/workspaces/{wid}/toxic-flows/analyze", json={"persist_findings": False})
    assert toxic.status_code == 200
    assert "flows" in toxic.json()

    dual = client.post(f"/workspaces/{wid}/dual-llm/lint", json={"persist_findings": False})
    assert dual.status_code == 200

    tri = client.post(f"/workspaces/{wid}/scorecard/trifecta", json={})
    assert tri.status_code == 200
    assert tri.json()["scorecard"]["schema_id"] == "isovane.trifecta.v1"

    studio = client.get(f"/workspaces/{wid}/studio")
    assert studio.status_code == 200

import io
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from isovane_serve import workspaces as ws
from isovane_serve.main import app
from isovane_serve.repo import extract_archive


def test_extract_zip(tmp_path: Path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("agent/app.py", "import subprocess\nsubprocess.run('x', shell=True)\n")
        zf.writestr("agent/node_modules/x.js", "should skip")
    root, temp = extract_archive(buf.getvalue(), "agent.zip")
    try:
        assert (root / "app.py").exists() or (root / "agent" / "app.py").exists()
        files = [p.name for p in root.rglob("*") if p.is_file()]
        assert "x.js" not in files
    finally:
        from isovane_serve.repo import cleanup_temp

        cleanup_temp(temp)


def test_analyze_archive_endpoint(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ISOVANE_DATA_DIR", str(tmp_path))
    ws.store = ws.WorkspaceStore()
    client = TestClient(app)

    created = client.post("/workspaces", json={"name": "zip-scan", "description": "t"})
    assert created.status_code == 201
    wid = created.json()["id"]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "bot/tool.py",
            "import subprocess\nsubprocess.run(['echo'], shell=True)\n",
        )
    buf.seek(0)
    response = client.post(
        "/analyze/archive",
        data={"workspace_id": wid},
        files={"file": ("bot.zip", buf.getvalue(), "application/zip")},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "findings" in payload
    assert payload["job"]["status"] in {"done", "failed"}

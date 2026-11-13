"""MCP toxic-flow + attest depth (dev-time)."""

from __future__ import annotations

import json
from pathlib import Path

from isovane_serve.mcp_skills import scan_mcp_and_skills


def test_toxic_flow_read_fs_plus_exfil(tmp_path: Path):
    doc = {
        "mcpServers": {
            "combo": {
                "command": "npx",
                "args": ["-y", "demo-mcp@1.2.3"],
                "tools": ["read_file", "send_email"],
            }
        }
    }
    (tmp_path / "mcp.json").write_text(json.dumps(doc), encoding="utf-8")
    titles = [f.title for f in scan_mcp_and_skills("ws", tmp_path)]
    assert any("toxic flow" in t.lower() for t in titles)


def test_missing_attest_on_pinned_package(tmp_path: Path):
    doc = {
        "mcpServers": {
            "fs": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2"],
            }
        }
    }
    (tmp_path / "mcp.json").write_text(json.dumps(doc), encoding="utf-8")
    titles = [f.title for f in scan_mcp_and_skills("ws", tmp_path)]
    assert any("attested" in t.lower() for t in titles)


def test_attest_present_skips_warning(tmp_path: Path):
    doc = {
        "mcpServers": {
            "fs": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2"],
                "integrity": "sha256-deadbeef",
            }
        }
    }
    (tmp_path / "mcp.json").write_text(json.dumps(doc), encoding="utf-8")
    titles = [f.title for f in scan_mcp_and_skills("ws", tmp_path)]
    assert not any("attested" in t.lower() for t in titles)

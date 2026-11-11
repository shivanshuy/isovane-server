"""F4: structured MCP JSON pin / auth / wildcard walk."""

from __future__ import annotations

import json
from pathlib import Path

from isovane_serve.mcp_skills import scan_mcp_and_skills

ROOT = Path(__file__).resolve().parents[1]


def _titles(tmp_path: Path, doc: dict) -> list[str]:
    p = tmp_path / "mcp.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return [f.title for f in scan_mcp_and_skills("t", tmp_path)]


def test_walk_flags_unpinned_scoped_package(tmp_path: Path):
    titles = _titles(
        tmp_path,
        {
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                }
            }
        },
    )
    assert any("Unpinned" in t for t in titles)


def test_walk_accepts_pinned_version(tmp_path: Path):
    titles = _titles(
        tmp_path,
        {
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2"],
                }
            }
        },
    )
    assert not any("Unpinned" in t for t in titles)


def test_walk_flags_remote_without_auth(tmp_path: Path):
    titles = _titles(
        tmp_path,
        {"mcpServers": {"r": {"url": "https://mcp.example.com/sse"}}},
    )
    assert any("auth" in t.lower() for t in titles)


def test_walk_accepts_remote_with_auth_header(tmp_path: Path):
    titles = _titles(
        tmp_path,
        {
            "mcpServers": {
                "r": {
                    "url": "https://mcp.example.com/sse",
                    "headers": {"Authorization": "Bearer x"},
                }
            }
        },
    )
    assert not any("auth" in t.lower() for t in titles)


def test_walk_flags_wildcard_tools(tmp_path: Path):
    titles = _titles(
        tmp_path,
        {
            "mcpServers": {
                "x": {
                    "command": "npx",
                    "args": ["-y", "pkg@1.0.0"],
                    "tools": ["*"],
                }
            }
        },
    )
    assert any("Wildcard" in t for t in titles)


def test_bakeoff_mcp_fixtures_detected():
    for name in ("mcp_unpinned", "mcp_remote_auth", "mcp_wildcard_tools"):
        folder = ROOT / "tests" / "bakeoff" / "fixtures" / name
        titles = [f.title for f in scan_mcp_and_skills("bakeoff", folder)]
        blob = " ".join(titles).lower()
        if name == "mcp_unpinned":
            assert "unpinned" in blob
        elif name == "mcp_remote_auth":
            assert "auth" in blob
        else:
            assert "wildcard" in blob

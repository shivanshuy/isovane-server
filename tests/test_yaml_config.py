"""Config layout: prompts + scan settings load from YAML."""

from __future__ import annotations

from isovane_serve.yaml_config import load_prompts, load_scan_settings, skip_dir_names


def test_prompts_yaml_has_vision_and_risk():
    prompts = load_prompts()
    assert "reconstructing" in prompts["vision_extract"].lower()
    assert "structurizr" in prompts["architecture_risk"].lower()


def test_scan_yaml_skip_and_mcp_runners():
    assert ".venv" in skip_dir_names()
    mcp = load_scan_settings()["mcp"]
    assert "npx" in mcp["runners"]
    assert "authorization" in mcp["auth_header_keys"]
    ast = load_scan_settings()["ast_taint"]
    assert "SystemMessage" in ast["prompt_sinks"]

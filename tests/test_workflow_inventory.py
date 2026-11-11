from pathlib import Path

from isovane_serve.diagram import analyze_code_workflow
from isovane_serve.workflow_inventory import inventory_from_tree


def test_inventory_detects_langgraph_and_mcp(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "from langgraph.prebuilt import create_react_agent\n"
        "from langchain_openai import ChatOpenAI\n"
        "create_react_agent(ChatOpenAI(), tools)\n"
        "mcpServers = {}\n",
        encoding="utf-8",
    )
    inv = inventory_from_tree(tmp_path)
    assert inv["counts"].get("agent", 0) >= 1
    assert inv["counts"].get("llm", 0) >= 1


def test_analyze_code_workflow_findings(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from langgraph.prebuilt import create_react_agent\n"
        "agent = create_react_agent(model, tools)\n"
        "mcp = FastMCP('demo')\n"
        "@tool\ndef shell(cmd: str): ...\n",
        encoding="utf-8",
    )
    result = analyze_code_workflow("ws", tmp_path, mode="workflow")
    assert result["inventory"]["source"] == "code"
    assert len(result["findings"]) >= 1

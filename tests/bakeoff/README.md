# Detection bake-off harness (F1 + F4/F5/F7)

Compare Isovane analyze (+ LangGraph inventory where declared) against expected hints.  
Peer method vs LLMArmor: [COMPARISON.md](./COMPARISON.md).

## Fixtures

| Fixture | What it probes |
|---------|----------------|
| `agent_unsafe` | System-prompt interpolation + `shell=True` |
| `prompt_jailbreak` | Jailbreak / ignore-previous strings |
| `mcp_unpinned` | MCP JSON unpinned `npx` / `@latest` |
| `mcp_remote_auth` | Remote MCP URL without auth (structured walk) |
| `mcp_wildcard_tools` | MCP `tools: ["*"]` |
| `eval_exec` | `eval` on model output |
| `secret_hardcode` | Hardcoded API keys |
| `ast_taint_alias` | Aliased request JSON → `SystemMessage` |
| `langgraph_hitl_gap` | LangGraph topology inventory |

## Run

```powershell
cd isovane-server
poetry run python scripts/bakeoff_score.py
poetry run python scripts/bakeoff_compare_llmarmor.py
poetry run pytest tests/test_bakeoff.py tests/test_mcp_skills.py tests/test_ast_taint.py -q
```

CI runs the pytest gate and `bakeoff_score.py` (see `.github/workflows/isovane-scan.yml`).

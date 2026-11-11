# Isovane config

| File | Purpose |
|------|---------|
| `models.yaml` | Vision/risk model provider + model names (env overrides supported) |
| `prompts.yaml` | LLM prompts for diagram extract + architecture risk |
| `scan.yaml` | Skip dirs, file ext, Semgrep upstream, MCP runners/auth, AST taint catalog |
| `kinds.yaml` | Node-kind token tables (ui/agent/mcp/tool/llm/data/hitl) |

Python loads these via `isovane_serve.paths` + `isovane_serve.yaml_config` / `model_config`.  
Edit YAML for day-to-day tuning; keep Python for orchestration only.

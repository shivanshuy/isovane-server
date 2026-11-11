# Isovane config

| File | Purpose |
|------|---------|
| `models.yaml` | Vision/risk model provider + model names (env overrides supported) |
| `prompts.yaml` | LLM prompts for diagram extract + architecture risk |
| `scan.yaml` | Shared scan constants (skip dirs, MCP runners/auth keys, AST taint catalog) |

Python loads these via `isovane_serve.paths` + `isovane_serve.yaml_config` / `model_config`.  
Edit YAML for day-to-day tuning; keep Python for orchestration only.

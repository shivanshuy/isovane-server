# Bake-off comparison method: Isovane vs LLMArmor

**Status:** published method (F7)  
**Date:** 11 Nov 2026  
**Scripts:** `scripts/bakeoff_score.py`, `scripts/bakeoff_compare_llmarmor.py`

## Goal

Compare **detection recall** on a shared fixture corpus so Isovane does not claim static-analysis parity without evidence. LLMArmor is the primary peer for **Python AST / OWASP LLM source** scanning.

## Corpus

Fixtures under `tests/bakeoff/fixtures/` with expected substring hints in `tests/bakeoff/expected/`.

| Fixture | Probes |
|---------|--------|
| `agent_unsafe` | System-prompt interpolation + `shell=True` |
| `prompt_jailbreak` | Jailbreak / ignore-previous strings |
| `mcp_unpinned` | MCP JSON unpinned `npx` / `@latest` |
| `mcp_remote_auth` | Remote MCP URL without auth fields |
| `mcp_wildcard_tools` | MCP `tools: ["*"]` |
| `eval_exec` | `eval` on model output |
| `secret_hardcode` | Hardcoded API keys |
| `ast_taint_alias` | Aliased `request.json` → `SystemMessage` |
| `langgraph_hitl_gap` | LangGraph inventory (Isovane-specific; not scored against LLMArmor fairness) |

## Scoring rules

1. Run each engine on the **fixture directory** (not the whole monorepo).  
2. Collect finding titles / messages into one lowercase blob.  
3. `finding_recall = (# expected substrings found) / (# expected substrings)`.  
4. Expected substrings are **hints**, not full OWASP IDs — they encode the security concept (e.g. `pin`, `auth`, `taint`, `system`).  
5. CI gate for Isovane alone: `bakeoff_score.py` requires ≥5 fixtures and recall ≥ 0.5 each.  
6. Side-by-side: `bakeoff_compare_llmarmor.py` writes `last_compare.json`. If LLMArmor is missing, Isovane rows are still recorded and `llmarmor.available=false`.

## How to run

```powershell
cd isovane-server
poetry run python scripts/bakeoff_score.py
poetry run python scripts/bakeoff_compare_llmarmor.py
# optional peer install (not a hard dependency of Isovane):
pip install llmarmor
poetry run python scripts/bakeoff_compare_llmarmor.py
```

## Fairness notes

- **MCP JSON pin/auth/wildcard** and **LangGraph → Structurizr** are Isovane workbench strengths; LLMArmor may score low on those fixtures by design — that is not a failure of either tool.  
- **AST prompt taint** (`ast_taint_alias`, `agent_unsafe`) is the fairest head-to-head slice.  
- Do **not** average all fixtures into a single “Isovane beats LLMArmor” headline; report per-fixture and call out category differences.  
- Architecture / privacy board / Hunt gate are **out of scope** for this comparison.

## Claiming parity

Only claim static detection parity after:

1. This method is linked from release notes / positioning.  
2. On the **AST/prompt** subset, Isovane recall is competitive (target: ≥ LLMArmor on `ast_taint_alias` + `agent_unsafe`, or documented gaps).  
3. CI bake-off stays green.

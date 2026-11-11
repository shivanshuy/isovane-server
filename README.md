# isovane-server

Analyze → Watch → Fix for agent security. REST on `8092`; LangGraph gate on `2026`.

| Service | Command | Port |
|---------|---------|------|
| REST API | `poetry run isovane-serve` | `8092` |
| LangGraph | `poetry run langgraph dev --port 2026 --no-reload` | `2026` (graph id **`gate`**) |

The action verdict is deterministic policy in `gate.py`. The model is not on that path.

## Install

```bash
cd isovane-server
poetry install
copy .env.example .env
```

Analyze engines (all free OSS): **Semgrep CE** (local `rules/agent` **composed with** Registry `p/ai-best-practices`), **Bandit**, **detect-secrets**, **promptlint**, **MCP/skills + AST taint**, **Presidio** (optional extra). Set `ISOVANE_SEMGREP_UPSTREAM=0` to skip the Registry pack (air-gapped).

```bash
# CLI / CI (no API required)
poetry run isovane-scan . --sarif out.sarif --fail-on high

# Optional deeper PII / OCR for architecture images
poetry install -E pii
poetry install -E ocr
# Vision extract (Ollama): ollama pull llava
```

### Suppressions

Place in the scanned repo root:

- **`.isovaneignore`** — one path glob per line (`vendor/**`, `*.generated.py`). Lines starting with `#` are comments.
- **`.isovane-baseline.json`** — array of `{ "title", "path", "rule_id" }` (or string keys) to silence known accepted findings.

```bash
# Optional deeper PII
poetry install -E pii
# or: pip install "presidio-analyzer[gliner]" presidio-anonymizer gliner
```

## Core APIs

- `GET /health`
- `GET /workspaces`, `GET /workspaces/{id}` (includes `gate` stats)
- `PUT /workspaces/{id}/policy`
- `POST /analyze` — folder / prompts / text blobs → Findings
- `POST /analyze/diagram` — multipart image or text; `POST /analyze/diagram/json`
  - `mode`: `privacy` (org→OpenAI/Anthropic residency/PII), `workflow` (UI/agent/MCP graph), or `both`
  - `folder`: optional Agentic Radar–style inventory from a source tree
- `GET /findings?workspace_id=&status=`
- `POST /gates` — sidecar contract; deny creates Finding + Trace
- `GET /traces`, `GET /traces/{id}`
- `POST /hunt/run` — deterministic gate scenarios (poison email, refund, shell, …)
- `POST /fixes/{finding_id}` — copyable patch
- `GET /export/sarif?workspace_id=`

OpenAPI: http://127.0.0.1:8092/docs

## CI gate

```bash
# Preferred: direct scan + SARIF
poetry run isovane-scan . --sarif isovane.sarif --fail-on high

# Or with API + hunt pack
poetry run python scripts/ci_gate.py --workspace checkout-agent
```

GitHub Action: [`.github/workflows/isovane-scan.yml`](.github/workflows/isovane-scan.yml)

## Semgrep rules (2A compose)

`POST /analyze` and `isovane-scan` run:

1. Local Isovane pack: `rules/agent/` (LangChain/LangGraph, prompt safety, tool misuse, LLM agency)
2. Upstream: Semgrep `p/ai-best-practices` when network allows

```bash
semgrep scan --config rules/agent --config p/ai-best-practices --metrics=off /path/to/agent/repo
```

## Sidecar

See `scripts/sidecar_example.py` — wrap tool invoke with `POST /gates`.

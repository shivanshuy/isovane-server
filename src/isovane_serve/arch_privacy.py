"""Architecture mode 1: org → multi-cloud LLM data privacy / residency risks."""

from __future__ import annotations

from typing import Any

from isovane_serve.insights import insight_for
from isovane_serve.remediations import apply_remediation_fields
from isovane_serve.models import Finding, FindingEvidence, SuggestedFix

# Vendor / region tokens for egress classification.
_LLM_CLOUDS: dict[str, tuple[str, str]] = {
    "openai": ("OpenAI", "US / multi-region vendor cloud"),
    "anthropic": ("Anthropic", "US vendor cloud"),
    "claude": ("Anthropic", "US vendor cloud"),
    "azure openai": ("Azure OpenAI", "Customer-chosen Azure region (still Microsoft cloud)"),
    "azureopenai": ("Azure OpenAI", "Customer-chosen Azure region (still Microsoft cloud)"),
    "bedrock": ("AWS Bedrock", "AWS region"),
    "amazon bedrock": ("AWS Bedrock", "AWS region"),
    "vertex": ("Google Vertex AI", "GCP region"),
    "gemini": ("Google Gemini / Vertex", "GCP / Google cloud"),
    "cohere": ("Cohere", "Vendor cloud"),
    "mistral": ("Mistral", "EU/US vendor cloud"),
    "groq": ("Groq", "Vendor cloud"),
    "together": ("Together AI", "Vendor cloud"),
    "fireworks": ("Fireworks", "Vendor cloud"),
    "ollama": ("Ollama (local)", "On-prem / local — lower egress risk"),
    "vllm": ("vLLM (self-host)", "Self-hosted — control plane stays yours"),
    "huggingface": ("Hugging Face Inference", "HF / partner cloud"),
}

_DATA_TOKENS = (
    "customer",
    "pii",
    "personal",
    "email",
    "ssn",
    "phone",
    "health",
    "hipaa",
    "gdpr",
    "payroll",
    "secret",
    "credential",
    "document",
    "ticket",
    "crm",
    "ehr",
)

_PROTECT_TOKENS = (
    "redact",
    "anonymiz",
    "tokenize",
    "dlp",
    "mask",
    "pseudonym",
    "vault",
    "kms",
    "encrypt",
    "tls",
    "mtls",
    "private link",
    "privatelink",
    "vpc",
    "zero data retention",
    "zdr",
    "no training",
    "eu-only",
    "residency",
)


def analyze_privacy(
    workspace_id: str,
    text: str,
    *,
    filename: str | None = None,
    nodes: list[dict[str, Any]] | None = None,
) -> list[Finding]:
    lower = text.lower()
    findings: list[Finding] = []
    clouds = _detect_llm_clouds(lower)
    has_org = any(
        t in lower
        for t in ("org", "organization", "enterprise", "vpc", "on-prem", "onprem", "intranet", "customer")
    )
    has_data = any(t in lower for t in _DATA_TOKENS)
    has_protect = any(t in lower for t in _PROTECT_TOKENS)
    has_training_opt_out = any(
        t in lower for t in ("zero data retention", "zdr", "no training", "opt-out", "opt out", "data retention")
    )
    has_logging = any(t in lower for t in ("log", "observability", "langsmith", "helix", "datadog", "sentry"))
    multi_vendor = len(clouds) >= 2

    if clouds and (has_org or has_data or "prompt" in lower or "llm" in lower):
        names = ", ".join(c[0] for c in clouds)
        regions = "; ".join(f"{c[0]} → {c[1]}" for c in clouds)
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Organizational data egress to LLM vendor clouds",
                (
                    f"Diagram routes org/customer content to external model hosts ({names}). "
                    f"Residency map: {regions}. Once prompts leave the org boundary, the vendor "
                    "processes/retains per their DPA — not your VPC controls."
                ),
                ["LLM02", "ASI10"],
                "high",
                [
                    "Prefer regional Azure OpenAI / Bedrock / Vertex in your approved region",
                    "Contractual ZDR / no-training; verify logging sinks",
                    "Minimize payload: redact PII before the cloud hop",
                ],
                "Insert a DLP/redact gateway before any SaaS LLM; pin region + ZDR in the vendor contract.",
                tags=["Privacy & cloud", "Data residency"],
                region="org→llm-cloud",
                extra={"clouds": [c[0] for c in clouds]},
            )
        )

    if multi_vendor:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Multi-cloud LLM fan-out increases privacy surface",
                (
                    "The same agent path can send data to more than one model vendor "
                    f"({', '.join(c[0] for c in clouds)}). Each hop is a separate processor, "
                    "sub-processor chain, and breach/notification domain."
                ),
                ["LLM02", "ASI03"],
                "high",
                [
                    "Pick one approved model host per data class",
                    "Label which prompts may leave which trust zone",
                    "Block dual-vendor routing for regulated datasets",
                ],
                "Converge on a single approved LLM landing zone per sensitivity tier.",
                tags=["Privacy & cloud", "Multi-cloud"],
                region="multi-llm",
            )
        )

    if has_data and clouds and not has_protect:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Customer/PII path to cloud LLM without redact/DLP",
                (
                    "Customer or personal data appears on a path that reaches an external LLM, "
                    "but the diagram has no redact, DLP, tokenize, or vault step before egress."
                ),
                ["LLM02"],
                "critical",
                [
                    "Add redact/tokenize before OpenAI/Anthropic/Bedrock calls",
                    "Classify fields; never send raw identifiers in prompts",
                    "Log hashes only — not raw PII — in traces",
                ],
                "Place a mandatory PII filter between org data stores and the LLM client.",
                tags=["Privacy & cloud", "PII"],
                region="data→llm",
            )
        )

    if clouds and not has_training_opt_out and not any(
        c[0].startswith("Ollama") or "Self-host" in c[1] or "On-prem" in c[1] for c in clouds
    ):
        findings.append(
            _finding(
                workspace_id,
                filename,
                "No zero-data-retention / no-training marker on LLM edge",
                (
                    "External LLM edges lack an explicit ZDR / no-training / retention control. "
                    "Default SaaS terms may allow broader use or longer retention than your policy."
                ),
                ["LLM02", "LLM03"],
                "medium",
                [
                    "Enable vendor ZDR / enterprise no-training",
                    "Document retention TTL on the architecture",
                    "Prefer private endpoints (Private Link) where available",
                ],
                "Annotate each LLM edge with ZDR + retention TTL; enforce in the client SDK config.",
                tags=["Privacy & cloud", "Retention"],
                region="llm-contract",
            )
        )

    if has_logging and clouds:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Observability sink may duplicate prompt data outside org",
                (
                    "Logging/observability appears alongside LLM usage. Traces often capture full "
                    "prompts/completions — a second egress channel (LangSmith, Datadog, etc.)."
                ),
                ["LLM02"],
                "medium",
                [
                    "Redact traces; disable prompt capture in prod",
                    "Keep observability in the same residency zone as the app",
                    "Treat trace stores as in-scope for DPA reviews",
                ],
                "Turn off raw prompt logging or redact before shipping spans to third-party APM.",
                tags=["Privacy & cloud", "Logging"],
                region="llm→logs",
            )
        )

    saas_db = any(t in lower for t in ("salesforce", "snowflake", "bigquery", "dynamodb", "cosmos"))
    if saas_db and clouds:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "SaaS data store → LLM cloud crosses two processors",
                (
                    "Data may flow SaaS datastore → your app → LLM vendor. Two (or more) cloud "
                    "processors see the content; map each hop for GDPR Art. 28 / transfer risk."
                ),
                ["LLM02", "ASI10"],
                "medium",
                [
                    "Draw processor vs controller roles on the diagram",
                    "Minimize fields pulled from SaaS before prompting",
                ],
                "Document lawful basis and SCCs for every cross-cloud hop.",
                tags=["Privacy & cloud"],
                region="saas→llm",
            )
        )

    local_ok = any(c[0].startswith("Ollama") or "Self-host" in c[1] for c in clouds)
    if local_ok and has_data:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Self-hosted model path reduces egress — verify isolation",
                (
                    "A local/self-hosted model appears on the graph. That helps residency, but "
                    "GPU hosts, shared caches, and admin access still need isolation controls."
                ),
                ["LLM02"],
                "low",
                [
                    "Keep inference NIC off the public internet",
                    "Separate tenancy for regulated workloads",
                ],
                "Treat self-host GPUs as a high-trust enclave with IAM + disk encryption.",
                tags=["Privacy & cloud", "Self-host"],
                region="local-llm",
            )
        )

    if not findings and text.strip():
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Privacy architecture needs cloud labels",
                (
                    "Could not map org → LLM cloud hops. Label vendors (OpenAI, Anthropic, Bedrock…), "
                    "data stores with PII, and any redact/ZDR controls."
                ),
                ["ASI10"],
                "low",
                ["Annotate LLM vendor + region on each model node", "Mark PII stores and DLP gates"],
                "Add vendor/region and data-class labels so privacy analysis can run.",
                tags=["Privacy & cloud"],
                region="unclassified",
            )
        )

    # Attach simple inventory hint for UI
    for f in findings:
        if f.evidence.args is None:
            f.evidence.args = {}
        f.evidence.args["analysis_mode"] = "privacy"
        if nodes is not None:
            f.evidence.args["node_count"] = len(nodes)
    return findings


def _detect_llm_clouds(lower: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key, meta in sorted(_LLM_CLOUDS.items(), key=lambda kv: -len(kv[0])):
        if key in lower and meta[0] not in seen:
            found.append(meta)
            seen.add(meta[0])
    return found


def _finding(
    workspace_id: str,
    filename: str | None,
    title: str,
    summary: str,
    owasp: list[str],
    severity: str,
    checklist: list[str],
    fix_summary: str,
    *,
    tags: list[str],
    region: str,
    extra: dict[str, Any] | None = None,
) -> Finding:
    insight = insight_for(title=title, issue_text=summary, tool="architecture-privacy")
    args: dict[str, Any] = {"analysis_mode": "privacy", "diagram_region": region}
    if extra:
        args.update(extra)
    fields = insight.as_finding_fields(owasp)
    merged_tags = list(dict.fromkeys([*(fields.get("tags") or []), *tags]))
    fields["tags"] = merged_tags
    suggested = apply_remediation_fields(
        title=title,
        owasp=owasp,
        category="architecture",
        path=filename,
        existing=SuggestedFix(
            kind="architecture",
            summary=fix_summary,
            checklist=insight.merge_checklist(checklist),
        ),
    )
    if suggested.checklist:
        fields["solutions"] = list(suggested.checklist)
    return Finding(
        workspace_id=workspace_id,
        source="analyze",
        severity=severity,  # type: ignore[arg-type]
        title=title,
        category="architecture",
        evidence=FindingEvidence(
            path=filename,
            diagram_region=region,
            snippet=summary[:240],
            tool="architecture-privacy",
            args=args,
        ),
        suggested_fix=suggested,
        **fields,
    )

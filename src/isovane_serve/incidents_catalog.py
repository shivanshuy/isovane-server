"""Documented real-world incidents only — used to show multiple case files per finding.

Sources are public reporting / vendor disclosures / peer-reviewed or industry research.
Do not invent incidents; if unsure, omit.
"""

from __future__ import annotations

from typing import TypedDict


class IncidentDict(TypedDict):
    headline: str
    when: str
    story: str
    technical: str
    source: str


# --- Classic AppSec ---

OPEN_BIND: list[IncidentDict] = [
    {
        "headline": "MongoDB ransom wave — tens of thousands of open databases",
        "when": "January 2017",
        "story": (
            "Attackers used internet-wide scans (including Shodan) to find MongoDB instances "
            "listening on the public internet with no authentication. They wiped or replaced "
            "data with ransom notes demanding Bitcoin. Researchers tracked on the order of "
            "roughly 29,000–34,000 impacted MongoDB instances in the first wave; many operators "
            "who paid did not recover data."
        ),
        "technical": (
            "Default/misconfigured MongoDB bound to 0.0.0.0:27017 without auth. Same pattern "
            "hit Redis earlier and Elasticsearch within days of the MongoDB wave."
        ),
        "source": "Krebs on Security (Jan 2017); SecurityWeek / Victor Gevers reporting",
    },
    {
        "headline": "Elasticsearch ransack after MongoDB",
        "when": "January 2017",
        "story": (
            "Within days of the MongoDB campaign, the same class of attackers moved to "
            "internet-exposed Elasticsearch clusters. Hundreds of hosts were hijacked quickly "
            "while tens of thousands of Elasticsearch instances remained reachable on the public "
            "internet (Shodan estimates around that period cited ~35,000)."
        ),
        "technical": (
            "Search/analytics engines left on public IPs without proper network controls — "
            "the same 'bound all interfaces / no edge auth' failure mode as open databases."
        ),
        "source": "BleepingComputer; SecurityWeek (Jan 2017)",
    },
    {
        "headline": "Redis and other NoSQL services in the same exposure class",
        "when": "2016–2017 (recurring)",
        "story": (
            "Security reporting documented unprotected Redis instances being targeted before "
            "and alongside the MongoDB wave. The lesson repeated: services meant for private "
            "networks that bind to all interfaces get found by mass scanners within hours."
        ),
        "technical": "Unauthenticated Redis/Memcached/Mongo/ES on public IP → wipe, ransom, or botnet use.",
        "source": "Duo / Summit Route summaries of 2016–2017 exposure campaigns",
    },
    {
        "headline": "Memcached amplification DDoS — open UDP services as weapons",
        "when": "February–March 2018",
        "story": (
            "Attackers abused internet-exposed Memcached servers (UDP port 11211) as "
            "amplifiers in record-breaking DDoS attacks, including traffic reported above "
            "1 Tbps against targets such as GitHub. The root cause was the same class of "
            "mistake: a cache meant for a private network left reachable on the public internet."
        ),
        "technical": "Publicly reachable Memcached → UDP amplification → third-party DDoS impact.",
        "source": "Akamai / Cloudflare / GitHub incident reporting on the 2018 Memcached DDoS wave",
    },
]

SSRF: list[IncidentDict] = [
    {
        "headline": "Capital One — SSRF via misconfigured WAF to AWS metadata",
        "when": "March 2019 (disclosed July 2019)",
        "story": (
            "An attacker exploited a server-side request forgery path through a misconfigured "
            "web application firewall in Capital One's AWS environment, reached the instance "
            "metadata service, obtained credentials, and accessed S3 data. Capital One reported "
            "impact to about 100 million people in the US and about 6 million in Canada."
        ),
        "technical": (
            "SSRF → AWS IMDS → temporary credentials → list/read S3. AWS and Capital One "
            "emphasized application/WAF misconfiguration and overly broad permissions — not a "
            "novel zero-day in AWS itself."
        ),
        "source": "Capital One Facts 2019; Krebs on Security; AWS statements to Congress",
    },
    {
        "headline": "Shopify Exchange SSRF → cloud metadata / container root (bug bounty)",
        "when": "2018 (HackerOne #341876)",
        "story": (
            "A researcher reported SSRF in Shopify Exchange screenshotting that could reach "
            "cloud metadata and lead to root access within an infrastructure subset. Shopify "
            "disabled the service quickly, audited subsets, deployed metadata concealment, and "
            "restricted internal IP access; bounty paid $25,000."
        ),
        "technical": "User-influenced URL fetch from privileged infra → metadata service → credential/host impact.",
        "source": "HackerOne report #341876 (Shopify summary)",
    },
    {
        "headline": "Jira CVE-2019-8451 — widespread cloud metadata leakage via SSRF",
        "when": "2019 (Unit 42 study)",
        "story": (
            "Palo Alto Networks Unit 42 studied unauthenticated SSRF in Jira (CVE-2019-8451) "
            "across public-cloud deployments. Of 7,000+ internet-facing Jira instances found in "
            "six CSPs, about 45% were still vulnerable; of those, over half leaked cloud "
            "infrastructure metadata — the same metadata class involved in Capital One."
        ),
        "technical": "Unauth SSRF in a popular app → IMDS/metadata URL fetch from thousands of hosts.",
        "source": "Palo Alto Unit 42 SSRF / Jira CVE-2019-8451 research",
    },
]

SECRETS_GIT: list[IncidentDict] = [
    {
        "headline": "Uber 2016 — AWS keys from GitHub → 57 million records",
        "when": "October 2016 (disclosed November 2017)",
        "story": (
            "Attackers obtained credentials from a GitHub repository used by Uber engineers, "
            "used them to access an Amazon S3 archive, and obtained data affecting about "
            "57 million Uber users and drivers. Uber later disclosed it had paid the attackers "
            "$100,000 and delayed public notification."
        ),
        "technical": "Secrets in VCS → cloud API access → bulk PII exfiltration.",
        "source": "Uber disclosure / Bloomberg and BankInfoSecurity reporting",
    },
    {
        "headline": "Uber 2014 — earlier AWS key exposure via GitHub",
        "when": "2014",
        "story": (
            "Uber had a prior incident in which an adversary accessed AWS data using a "
            "GitHub-posted access key, affecting sensitive data for more than 100,000 drivers. "
            "The FTC later required long-term privacy audits related to Uber's data mishandling."
        ),
        "technical": "Same root cause family: cloud keys committed or exposed via source control.",
        "source": "Securonix / FTC-related reporting on Uber's 2014 incident",
    },
    {
        "headline": "Starbucks — JumpCloud API key found in a GitHub repository",
        "when": "January 2020 (publicly cited example)",
        "story": (
            "Industry reporting on secrets sprawl cites a Starbucks-related case where a "
            "JumpCloud API key discovered in a GitHub repository granted unauthorized access "
            "paths — another instance of the 'key in git' pattern that scanners exist to catch."
        ),
        "technical": "Hardcoded/committed API token in a repo → admin/API access beyond intended scope.",
        "source": "CSO Online / DZone summaries of publicly disclosed GitHub secret breaches",
    },
]

SHELL_INJECTION: list[IncidentDict] = [
    {
        "headline": "Shellshock (CVE-2014-6271) — attacker text became bash commands",
        "when": "September 2014",
        "story": (
            "The Bash 'Shellshock' vulnerability let attackers smuggle commands through "
            "environment variables processed by Bash (often via CGI). Mass exploitation followed "
            "quickly across internet-facing services — a canonical example of untrusted text "
            "reaching a shell interpreter."
        ),
        "technical": "Untrusted input → shell/Bash evaluation path → remote command execution at scale.",
        "source": "CVE-2014-6271 public advisories and contemporaneous incident response reporting",
    },
    {
        "headline": "Equifax 2017 — unpatched Struts RCE (not shell=True, same lesson class)",
        "when": "2017",
        "story": (
            "Equifax's breach exploited an unpatched Apache Struts remote code execution flaw "
            "(CVE-2017-5638), exposing data on roughly 147 million people. It underscores why "
            "dangerous execution sinks and delayed patching of known RCE classes become "
            "company-defining incidents."
        ),
        "technical": "Known RCE class left reachable on an internet-facing app → massive PII impact.",
        "source": "Equifax / U.S. congressional and GAO reporting on the 2017 breach",
    },
    {
        "headline": "ImageTragick (CVE-2016-3714) — filename/argument injection into ImageMagick",
        "when": "2016",
        "story": (
            "ImageMagick's ImageTragick issues let attackers craft image files or filenames that "
            "caused the library to run shell commands (via poorly constrained delegates). It became "
            "a widely cited example of 'user-influenced strings reaching a command interpreter' "
            "in application pipelines."
        ),
        "technical": "Untrusted content/args → shell-backed processing → remote code execution.",
        "source": "ImageTragick.com / CVE-2016-3714 advisories",
    },
]

# --- LLM / agent ---

PROMPT_INJECTION: list[IncidentDict] = [
    {
        "headline": "Slack AI — indirect prompt injection via public channel (PromptArmor)",
        "when": "August 2024",
        "story": (
            "Researchers at PromptArmor showed that a crafted message in a public Slack channel "
            "could be retrieved by Slack AI alongside private-channel content, causing the "
            "assistant to exfiltrate secrets (for example API keys) the attacker could not "
            "otherwise read — classic indirect injection over a mixed-trust corpus."
        ),
        "technical": "RAG over public+private content → malicious instructions in retrieved text → exfil via rendered links.",
        "source": "PromptArmor disclosure (Aug 2024); industry case-study roundups",
    },
    {
        "headline": "EchoLeak — zero-click prompt injection in Microsoft 365 Copilot",
        "when": "2025 (CVE-2025-32711)",
        "story": (
            "Aim Labs described EchoLeak: a crafted email could cause Microsoft 365 Copilot "
            "to pull internal data into a response and leak it without the user clicking a "
            "malicious link. Microsoft tracked the issue as CVE-2025-32711."
        ),
        "technical": "Untrusted email content enters enterprise RAG/assistant context → zero-click data exfiltration.",
        "source": "Aim Labs / arXiv EchoLeak write-up; NVD CVE-2025-32711",
    },
    {
        "headline": "GitLab Duo — remote prompt injection in merge requests / code",
        "when": "May 2025",
        "story": (
            "Legit Security reported that hidden prompts in merge requests and code could cause "
            "GitLab Duo to leak private source and inject malicious links — prompt injection "
            "against a coding assistant that reads attacker-influenced repository text."
        ),
        "technical": "Untrusted MR/code content → assistant context → private source / link injection.",
        "source": "Legit Security blog: remote prompt injection in GitLab Duo",
    },
]

RAG_TRUST: list[IncidentDict] = [
    {
        "headline": "Slack AI mixed-trust retrieval (same class as RAG without boundaries)",
        "when": "August 2024",
        "story": (
            "Slack AI's issue is specifically a trust-boundary failure: retrieved public-channel "
            "text was treated as influential instructions while private data was also in context. "
            "That is the production form of 'RAG concat without marking untrusted.' "
            "Impact was confidentiality loss across workspace trust levels — secrets an attacker "
            "could not read directly became reachable through the assistant."
        ),
        "technical": (
            "Attack chain: (1) Attacker posts crafted instructions in a public channel they can "
            "write to. (2) A user asks Slack AI a question that retrieves both that public text "
            "and private-channel material into one prompt context. (3) The model follows the "
            "untrusted retrieved instructions and surfaces private data (e.g. API keys) via the "
            "assistant answer or rendered links.\n\n"
            "Root cause: no hard separation between untrusted retrieved text and privileged "
            "private context. Retrieved chunks were concatenated into the same instruction "
            "stream as trusted system/user intent, so public text could act as a confused-deputy "
            "controller over private data already in context.\n\n"
            "Severity: high confidentiality impact in multi-tenant / multi-channel workspaces. "
            "Does not require malware on endpoints — only write access to a lower-trust corpus "
            "that the RAG path will retrieve. Same failure class as unmarked RAG concat in "
            "custom agent pipelines."
        ),
        "source": "PromptArmor Slack AI disclosure (Aug 2024)",
    },
    {
        "headline": "ConfusedPilot — academic demonstration of RAG confused-deputy risks",
        "when": "2024 (UT Austin research)",
        "story": (
            "Researchers published ConfusedPilot, showing how adversarial documents in a RAG "
            "corpus can corrupt answers and leak cached/secret context in Copilot-style systems. "
            "It is research, not a named enterprise breach, but it documents the RAG threat model "
            "with concrete integrity and confidentiality failures that production assistants inherit "
            "when retrieval is treated as trusted."
        ),
        "technical": (
            "Attack chain: (1) Adversary plants poisoned documents in a corpus the assistant will "
            "index/retrieve (shared drives, wikis, email-adjacent stores, etc.). (2) Benign user "
            "queries cause retrieval of those documents into the generation context. (3) Malicious "
            "content steers answers (integrity) and/or induces disclosure of other retrieved or "
            "cached privileged material (confidentiality).\n\n"
            "Root cause: RAG treats retrieved text as authoritative context without provenance, "
            "trust labels, or instruction/data separation. Caching of prior retrievals amplifies "
            "blast radius — a poisoned hit can influence later sessions beyond the original query.\n\n"
            "Severity: establishes that 'documents in the index' are an attacker-controlled "
            "control plane. Even without a public CVE name, this is the reference threat model "
            "for unmarked RAG: poisoned corpus + retrieval (+ caching) → integrity and "
            "confidentiality failures in Copilot-style systems."
        ),
        "source": "ConfusedPilot paper (arXiv 2408.04870, UT Austin)",
    },
    {
        "headline": "EchoLeak / Copilot email RAG path",
        "when": "2025",
        "story": (
            "EchoLeak again shows retrieved/ingested untrusted content (email) driving an "
            "enterprise assistant to disclose internal data — RAG/context trust failures in "
            "production. Microsoft tracked related impact as CVE-2025-32711. Severity is elevated "
            "because exploitation could require little or no user click once the malicious email "
            "was in the tenant's ingest/retrieval path."
        ),
        "technical": (
            "Attack chain: (1) Attacker delivers a crafted email into the victim tenant. "
            "(2) Microsoft 365 Copilot (or equivalent enterprise RAG path) retrieves/ingests "
            "that email content into assistant context with other internal material. (3) Hidden "
            "or adversarial instructions in the email cause the assistant to include internal "
            "data in an outbound response path — Aim Labs described zero-click style disclosure "
            "without requiring the user to open a malicious link.\n\n"
            "Root cause: untrusted document/email content enters the same retrieval/context "
            "window as privileged enterprise data, with insufficient isolation, sanitization, "
            "or policy gates on what retrieved text may instruct the model to do.\n\n"
            "Severity: critical/high enterprise confidentiality risk (CVE-2025-32711). "
            "Demonstrates that email and other inbound corpora are live attack surfaces for "
            "assistant RAG — not just 'chat prompts' the user typed. Same class as any agent "
            "that concatenates retrieved untrusted documents with secrets or internal knowledge."
        ),
        "source": "CVE-2025-32711 / Aim Labs EchoLeak research; NVD",
    },
]

EXCESSIVE_AGENCY: list[IncidentDict] = [
    {
        "headline": "Replit agent deleted a production database during a code freeze",
        "when": "July 2025",
        "story": (
            "Reporting around a SaaStr / Replit incident described an AI coding agent deleting "
            "a production database despite instructions not to make changes during a freeze — "
            "a concrete excessive-agency / insufficient HITL failure in an autonomous coding agent."
        ),
        "technical": "Agent had destructive tool power without an effective external gate.",
        "source": "The Register (Jul 2025) coverage of the Replit vibe-coding incident",
    },
    {
        "headline": "Amazon Q Developer extension — malicious prompt in a pull request",
        "when": "July 2025",
        "story": (
            "Security reporting described a supply-chain incident in which a malicious prompt "
            "landed in Amazon's Q Developer GitHub extension via a pull request, including "
            "destructive instructions (a 'wiper'-style payload). Amazon pulled and replaced the "
            "extension versions after disclosure."
        ),
        "technical": "Poisoned agent/extension instructions → potential destructive local actions.",
        "source": "404 Media / contemporaneous coverage of the Amazon Q GitHub extension incident (Jul 2025)",
    },
    {
        "headline": "GitHub MCP toxic-agent flow — private data via public issue",
        "when": "May 2025",
        "story": (
            "Invariant Labs showed that a malicious public GitHub issue could steer an agent "
            "using the GitHub MCP server into leaking private repository data into a public "
            "pull request — tool/MCP agency plus untrusted content."
        ),
        "technical": "Untrusted issue text + privileged MCP tools → cross-repo data leak.",
        "source": "Invariant Labs: MCP GitHub vulnerability write-up",
    },
    {
        "headline": "Zenity / Copilot Studio agent tool exfiltration (research demo)",
        "when": "Documented in MITRE ATLAS case studies",
        "story": (
            "Zenity researchers demonstrated prompt injection against a Copilot Studio–style "
            "customer-service agent that could retrieve CRM/RAG data and exfiltrate it through "
            "the agent's email tool — agency without a robust policy gate."
        ),
        "technical": "Injected instructions → RAG/CRM read tools → email send tool as exfil channel.",
        "source": "MITRE ATLAS AML.CS0037 / Zenity Copilot Studio research",
    },
    {
        "headline": "Chevrolet of Watsonville chatbot — $1 Tahoe stunt",
        "when": "December 2023",
        "story": (
            "A dealership chatbot was prompted into agreeing to sell a Chevy Tahoe for $1 — "
            "widely covered as unconstrained chatbot commitments without business-rule gates."
        ),
        "technical": "LLM free-text commitments without price/policy enforcement outside the model.",
        "source": "Contemporary news coverage of the Chevy Watsonville chatbot incident (Dec 2023)",
    },
]

MCP_SUPPLY: list[IncidentDict] = [
    {
        "headline": "Asana MCP cross-tenant exposure",
        "when": "June 2025",
        "story": (
            "Asana took its MCP server offline for about two weeks after a logic bug that could "
            "have exposed one organization's Asana data to MCP users in other organizations."
        ),
        "technical": "MCP server trust-boundary / tenancy bug in a new agent integration surface.",
        "source": "The Register reporting on Asana MCP outage (Jun 2025)",
    },
    {
        "headline": "Anthropic MCP Inspector RCE (CVE-2025-49596)",
        "when": "July 2025",
        "story": (
            "Oligo Security reported a critical issue in Anthropic's MCP Inspector developer "
            "tool: an unauthenticated proxy that could let a malicious website run code on a "
            "developer's machine."
        ),
        "technical": "Local MCP/dev tooling exposed without auth → browser-origin RCE path.",
        "source": "Oligo Security CVE-2025-49596 write-up",
    },
    {
        "headline": "mcp-remote OS command injection (CVE-2025-6514)",
        "when": "July 2025",
        "story": (
            "JFrog reported that the mcp-remote npm proxy could allow a malicious MCP server "
            "to run operating system commands on the client during connection setup."
        ),
        "technical": "Untrusted MCP server → client proxy command injection.",
        "source": "JFrog advisory CVE-2025-6514",
    },
]

PII_LLM: list[IncidentDict] = [
    {
        "headline": "Samsung — employees pasted source/meeting notes into ChatGPT",
        "when": "2023 (widely reported)",
        "story": (
            "Multiple outlets reported that Samsung semiconductor engineers pasted proprietary "
            "source code and meeting notes into ChatGPT, after which the company restricted "
            "generative AI use. Whether or not every detail of internal notes is public, the "
            "incident is the canonical corporate warning about sending sensitive data to "
            "external LLM clouds."
        ),
        "technical": "Org PII/IP → third-party LLM API with retention/training risk under default consumer terms.",
        "source": "Contemporary business/tech press coverage of Samsung ChatGPT restrictions (2023)",
    },
    {
        "headline": "OpenAI ChatGPT — brief exposure of other users' chat titles/history",
        "when": "March 2023",
        "story": (
            "OpenAI reported a bug related to a Redis client library that briefly allowed some "
            "users to see another active user's chat history titles and, in a subset of cases, "
            "payment-related information. It reinforced that LLM product stacks are still "
            "ordinary software with ordinary data-isolation failures."
        ),
        "technical": "Shared cache/session bug → cross-user disclosure of conversation metadata / billing fields.",
        "source": "OpenAI incident notice (March 2023)",
    },
    {
        "headline": "Italy Garante temporary ChatGPT ban over privacy concerns",
        "when": "March–April 2023",
        "story": (
            "Italy's data-protection authority (Garante) temporarily restricted ChatGPT over "
            "concerns including lack of a legal basis for training data and insufficient "
            "transparency/age controls — a regulatory incident driven by how personal data "
            "flows into generative AI systems."
        ),
        "technical": "Regulatory enforcement around LLM processing of personal data / transparency duties.",
        "source": "Garante per la protezione dei dati personali public orders (2023)",
    },
    {
        "headline": "Air Canada chatbot — incorrect refund policy held against the airline",
        "when": "2024 Canadian tribunal",
        "story": (
            "A Canadian civil resolution tribunal held Air Canada responsible for inaccurate "
            "bereavement-fare guidance given by its website chatbot. It is not a PII breach, "
            "but it shows production LLM output creating real legal/financial obligations."
        ),
        "technical": "Customer-facing LLM without reliable grounding/HITL → binding customer harm.",
        "source": "Civil Resolution Tribunal of British Columbia decision / press coverage (2024)",
    },
]

CHATBOT_AGENCY: list[IncidentDict] = [
    {
        "headline": "Chevrolet of Watsonville chatbot — $1 Tahoe stunt",
        "when": "December 2023",
        "story": (
            "A dealership chatbot built on ChatGPT was prompted into agreeing to sell a Chevy "
            "Tahoe for $1. The episode was widely documented as a demonstration of unconstrained "
            "chatbot commitments without business-rule gates."
        ),
        "technical": "LLM free-text commitments without price/policy enforcement outside the model.",
        "source": "Contemporary news coverage of the Chevy Watsonville chatbot incident (Dec 2023)",
    },
    {
        "headline": "Air Canada chatbot refund case",
        "when": "2024",
        "story": (
            "Air Canada's chatbot provided incorrect bereavement fare information; the tribunal "
            "found the airline liable for the chatbot's representations."
        ),
        "technical": "No reliable human/policy gate on consequential customer promises.",
        "source": "CRT BC / press coverage",
    },
]

DEFAULT_GENERAL: list[IncidentDict] = [
    OPEN_BIND[0],
    SECRETS_GIT[0],
    SSRF[0],
]

DEFAULT_LLM: list[IncidentDict] = [
    PROMPT_INJECTION[0],
    EXCESSIVE_AGENCY[0],
    RAG_TRUST[0],
]


def incidents_for_architecture(blob: str) -> list[IncidentDict]:
    """Real incident sets for architecture/diagram findings.

    Never fall through to classic AppSec catalogs (open bind, SSRF, git secrets) —
    those stories confuse diagram-control gaps. Prefer agentic / privacy cases.
    """
    b = blob.lower()
    if any(k in b for k in ("mcp", "model context")):
        return list(MCP_SUPPLY)
    if any(
        k in b
        for k in (
            "memory",
            "long-term context",
            "context poisoning",
            "vector store",
        )
    ):
        return list(RAG_TRUST)
    if any(
        k in b
        for k in (
            "mail path",
            "email",
            "echoleak",
        )
    ):
        return list(RAG_TRUST)
    if any(
        k in b
        for k in (
            "shell",
            "code-execution",
            "code execution",
            "code interpreter",
            "os-level agency",
        )
    ):
        return list(EXCESSIVE_AGENCY)
    if any(
        k in b
        for k in (
            "circuit breaker",
            "cascading",
            "rate limit",
            "blast radius",
            "policy gate",
            "intent gate",
            "per-agent identity",
            "scoped credentials",
            "swarm",
        )
    ):
        return list(EXCESSIVE_AGENCY)
    if any(
        k in b
        for k in (
            "hitl",
            "agency",
            "wildcard",
            "unrestricted tools",
            "a2a",
            "agent-to-agent",
            "agent to agent",
            "confirm",
            "approval",
        )
    ):
        return list(EXCESSIVE_AGENCY)
    if any(
        k in b
        for k in (
            "trust-boundary",
            "trust boundary",
            "untrusted",
            "prompt injection",
            "ingress",
            "jailbreak",
        )
    ):
        return list(PROMPT_INJECTION)
    if any(
        k in b
        for k in (
            "rag",
            "retrieved",
            "vector store",
            "knowledge base",
        )
    ):
        return list(RAG_TRUST)
    if any(
        k in b
        for k in (
            "privacy",
            "residency",
            "egress",
            "multi-cloud",
            "label",
            "unclassified",
            "pii",
            "vendor cloud",
            "cloud llm",
            "zdr",
            "openai",
            "anthropic",
            "bedrock",
        )
    ):
        return list(PII_LLM)
    if any(k in b for k in ("chatbot", "refund", "price")):
        return list(CHATBOT_AGENCY)
    return list(DEFAULT_LLM)


def incidents_for_blob(blob: str) -> list[IncidentDict]:
    """Pick the richest matching real-incident set for a finding blob."""
    b = blob.lower()
    if any(k in b for k in ("urlopen", "urllib", "ssrf", "url fetch", "requests.get")):
        return list(SSRF)
    if any(k in b for k in ("0.0.0.0", "bind_all", "all interfaces", "hardcoded_bind", "b104")):
        return list(OPEN_BIND)
    if any(k in b for k in ("secret", "api_key", "aws", "sk-", "detect-secrets", "hardcoded")):
        return list(SECRETS_GIT)
    if any(k in b for k in ("shell=true", "os.system", "subprocess", "command injection")):
        return list(SHELL_INJECTION)
    if any(k in b for k in ("mcp", "model context")):
        return list(MCP_SUPPLY)
    if any(
        k in b
        for k in (
            "rag",
            "retrieved",
            "vector store",
            "vector db",
            "knowledge base",
            "chroma",
            "pinecone",
            "faiss",
            "docstore",
        )
    ):
        return list(RAG_TRUST)
    if any(k in b for k in ("jailbreak", "ignore previous", "prompt injection", "indirect")):
        return list(PROMPT_INJECTION)
    if any(k in b for k in ("hitl", "agency", "bind_tools", "react agent", "confirm", "tool")):
        return list(EXCESSIVE_AGENCY)
    if any(k in b for k in ("pii", "openai", "anthropic", "residency", "egress", "disclosure")):
        return list(PII_LLM)
    if any(k in b for k in ("chatbot", "sold", "price", "refund")):
        return list(CHATBOT_AGENCY)
    if any(k in b for k in ("llm", "prompt", "agent", "copilot")):
        return list(DEFAULT_LLM)
    return list(DEFAULT_GENERAL)

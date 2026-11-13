"""Architecture diagram analysis — privacy/cloud + workflow graph modes."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

from isovane_serve.arch_privacy import analyze_privacy
from isovane_serve.arch_workflow import (
    analyze_workflow,
    classify_nodes,
    inventory_summary,
)
from isovane_serve.architecture_graph import (
    board_boundaries as boundaries_from_workspace,
    board_edges as edges_from_workspace,
    board_nodes as nodes_from_workspace,
    graph_from_parts,
    graph_to_analysis_text,
    graph_to_mermaid,
    normalize_graph,
    parse_architecture_graph,
)
from isovane_serve.diagram_graph import graph_from_text, parse_graph_json
from isovane_serve.image_diagram_seeds import generic_connected_seed, seed_for_filename
from isovane_serve.insights import insight_for
from isovane_serve.models import Finding, FindingEvidence, SuggestedFix
from isovane_serve.remediations import apply_remediation_fields
from isovane_serve.workflow_inventory import inventory_as_diagram_text, inventory_from_tree

ArchMode = Literal["privacy", "workflow", "both"]

TEXT_EXTENSIONS = {
    ".mmd",
    ".mermaid",
    ".puml",
    ".plantuml",
    ".pu",
    ".dot",
    ".gv",
    ".drawio",
    ".dio",
    ".xml",
    ".txt",
    ".md",
}
def analyze_diagram(
    workspace_id: str,
    *,
    mermaid: str | None = None,
    description: str | None = None,
    filename: str | None = None,
    format_hint: str | None = None,
    mode: ArchMode = "both",
    graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run privacy and/or workflow analysis. Returns findings + inventory.

    Canonical source of truth is a Structurizr / C4 workspace (`graph`).
    When provided (edited board), that workspace drives render + LLM/rules.
    Otherwise it is built from extracted/pasted diagram text.
    """
    arch_graph: dict[str, Any] | None = None
    if graph:
        arch_graph = normalize_graph(graph, source="board", filename=filename)
        text = graph_to_analysis_text(arch_graph)
    else:
        raw = "\n".join(part for part in (mermaid or "", description or "") if part).strip()
        text = normalize_diagram_text(raw, filename=filename, format_hint=format_hint)
        if not text:
            text = filename or ""
        parsed = parse_architecture_graph(text)
        if parsed and (
            (parsed.get("model") or {}).get("softwareSystems")
            or (parsed.get("model") or {}).get("people")
        ):
            arch_graph = normalize_graph(parsed, source="extract", filename=filename)
        else:
            nodes = _extract_nodes(text)
            typed = classify_nodes(text, nodes)
            built = graph_from_text(text, typed)
            arch_graph = graph_from_parts(
                built.get("nodes") or typed,
                built.get("edges") or [],
                source="extract",
                filename=filename,
            )
            text = graph_to_analysis_text(arch_graph)

    board_nodes = nodes_from_workspace(arch_graph)
    board_edges = edges_from_workspace(arch_graph)
    board_boundaries = boundaries_from_workspace(arch_graph)
    mermaid_view = graph_to_mermaid(arch_graph)

    findings: list[Finding] = []
    inventory: dict[str, Any] = {
        "source": "diagram",
        "mode": mode,
        **inventory_summary(
            board_nodes,
            edges=board_edges,
            board={
                "nodes": board_nodes,
                "edges": board_edges,
                "boundaries": board_boundaries,
            },
            mermaid=mermaid_view,
        ),
        "boundaries": board_boundaries,
        "graph": arch_graph,
    }
    risk_meta: dict[str, Any] = {"status": "rules", "message": "Rule catalog findings."}

    # LLM-first risk analyze on the same Structurizr workspace the board uses.
    llm_ok = False
    try:
        from isovane_serve import risk_diagram as risk_diagram_mod

        llm_result = risk_diagram_mod.analyze_risks_with_llm(
            workspace_id,
            graph=arch_graph,
            filename=filename,
            mode=mode,
        )
        findings = list(llm_result.get("findings") or [])
        if findings:
            llm_ok = True
            risk_meta = {
                "status": "llm",
                "provider": llm_result.get("provider"),
                "model": llm_result.get("model"),
                "message": (
                    f"LLM risk analyze ({llm_result.get('provider')}:{llm_result.get('model')}) "
                    "used the Structurizr/C4 workspace (same model as the board)."
                ),
            }
    except Exception as exc:  # noqa: BLE001
        risk_meta = {
            "status": "rules_fallback",
            "error": str(exc),
            "message": (
                f"LLM risk analyze failed ({exc}). Fell back to the architecture rule catalog."
            ),
        }

    if not llm_ok:
        if mode in ("privacy", "both"):
            findings.extend(
                analyze_privacy(workspace_id, text, filename=filename, nodes=board_nodes)
            )
        if mode in ("workflow", "both"):
            wf_findings, wf_inv = analyze_workflow(
                workspace_id, text, filename=filename, inventory=board_nodes
            )
            findings.extend(wf_findings)
            merged_nodes = wf_inv or board_nodes
            by_id = {str(n.get("id")): n for n in board_nodes}
            for node in merged_nodes:
                prev = by_id.get(str(node.get("id")))
                if prev:
                    if node.get("x") is None:
                        node["x"] = prev.get("x")
                    if node.get("y") is None:
                        node["y"] = prev.get("y")
            props = arch_graph.get("properties") if isinstance(arch_graph.get("properties"), dict) else {}
            kept_boundaries = boundaries_from_workspace(arch_graph)
            arch_graph = graph_from_parts(
                merged_nodes,
                board_edges,
                boundaries=kept_boundaries,
                source=str(props.get("isovane.source") or "extract"),
                filename=filename,
            )
            inventory = {
                "source": "diagram",
                "mode": mode,
                **inventory_summary(
                    merged_nodes,
                    edges=board_edges,
                    board={
                        "nodes": merged_nodes,
                        "edges": board_edges,
                        "boundaries": kept_boundaries,
                    },
                    mermaid=graph_to_mermaid(arch_graph),
                ),
                "boundaries": kept_boundaries,
                "graph": arch_graph,
            }
        if mode in ("workflow", "both"):
            findings.extend(_legacy_trust_rules(workspace_id, text, filename))

    findings = _dedupe(findings)
    inventory["risk"] = risk_meta
    inventory["graph"] = arch_graph
    try:
        from isovane_serve.privacy_posture import privacy_posture_from_graph

        inventory["privacy_posture"] = privacy_posture_from_graph(arch_graph)
    except Exception:  # noqa: BLE001 — never break analyze
        pass
    # Board remediation hints (titles only) — UI may show without changing layout.
    inventory["remediation_hints"] = [
        {
            "title": f.title,
            "summary": (f.suggested_fix.summary if f.suggested_fix else f.summary) or f.summary,
            "region": (f.evidence.args or {}).get("diagram_region") if f.evidence else None,
        }
        for f in findings[:12]
    ]
    return {"findings": findings, "inventory": inventory, "mode": mode, "text": text, "graph": arch_graph}


def analyze_code_workflow(
    workspace_id: str,
    folder: str | Path,
    *,
    mode: ArchMode = "workflow",
) -> dict[str, Any]:
    """Agentic Radar–style: infer UI/agent/MCP/tool graph from a source tree."""
    root = Path(folder).expanduser()
    inv = inventory_from_tree(root)
    text = inventory_as_diagram_text(inv)
    result = analyze_diagram(
        workspace_id,
        description=text,
        filename=f"workflow:{root.name}",
        format_hint="text",
        mode="workflow" if mode == "workflow" else mode,
    )
    # Prefer code inventory detail; keep Structurizr graph when inventory built one.
    merged_inv = {**(result.get("inventory") or {}), **inv, "mode": mode}
    if inv.get("graph"):
        merged_inv["graph"] = inv["graph"]
    if inv.get("board"):
        merged_inv["board"] = inv["board"]
    result["inventory"] = merged_inv
    if mode in ("privacy", "both"):
        # Also privacy-scan the flattened text (vendor imports show up as llm nodes)
        privacy_bits = analyze_privacy(
            workspace_id,
            text + "\n" + " ".join(
                n.get("label", "") for n in inv.get("nodes") or []
            ),
            filename=f"workflow:{root.name}",
        )
        merged = _dedupe([*result["findings"], *privacy_bits])
        result["findings"] = merged
    # Recompute hints after any finding merge so board hints stay fresh.
    findings_now = list(result.get("findings") or [])
    result.setdefault("inventory", {})["remediation_hints"] = [
        {
            "title": f.title,
            "summary": (f.suggested_fix.summary if f.suggested_fix else f.summary) or f.summary,
            "region": (f.evidence.args or {}).get("diagram_region") if f.evidence else None,
        }
        for f in findings_now[:12]
    ]
    try:
        from isovane_serve.privacy_posture import privacy_posture_from_graph

        graph = (result.get("inventory") or {}).get("graph") or result.get("graph")
        if graph:
            result["inventory"]["privacy_posture"] = privacy_posture_from_graph(graph)
    except Exception:  # noqa: BLE001
        pass
    # Persist Radar-class board for the workspace (survives restart).
    try:
        from isovane_serve.persistence import save_board

        board_payload = {
            "source": "code_inventory",
            "folder": str(root),
            "mode": mode,
            "board": (result.get("inventory") or {}).get("board"),
            "graph": (result.get("inventory") or {}).get("graph"),
            "counts": (result.get("inventory") or {}).get("counts"),
            "framework_graphs": (result.get("inventory") or {}).get("framework_graphs"),
            "langgraph_graphs": (result.get("inventory") or {}).get("langgraph_graphs"),
        }
        save_board(workspace_id, board_payload)
    except Exception:  # noqa: BLE001
        pass
    return result


def normalize_diagram_text(
    text: str,
    *,
    filename: str | None = None,
    format_hint: str | None = None,
) -> str:
    """Normalize Mermaid / PlantUML / Graphviz / Draw.io into analyzable text."""
    if not text:
        return ""
    hint = (format_hint or "").lower().strip()
    ext = Path(filename or "").suffix.lower()
    lower = text.lower()

    if hint in {"plantuml", "puml"} or ext in {".puml", ".plantuml", ".pu"} or "@startuml" in lower:
        return _from_plantuml(text)
    if hint in {"graphviz", "dot"} or ext in {".dot", ".gv"} or re.search(
        r"\bdigraph\b|\bgraph\b\s+\w+\s*\{", text
    ):
        return _from_graphviz(text)
    if hint in {"drawio", "diagrams.net"} or ext in {".drawio", ".dio"} or "<mxfile" in lower or "<mxgraphmodel" in lower:
        return _from_drawio(text)
    if hint in {"mermaid", "mmd"} or ext in {".mmd", ".mermaid"} or any(
        token in text for token in ("flowchart", "sequenceDiagram", "graph TD", "graph LR", "-->")
    ):
        return text
    return text


def analyze_upload_bytes(
    workspace_id: str,
    data: bytes,
    filename: str,
    format_hint: str | None = None,
    mode: ArchMode = "both",
) -> dict[str, Any]:
    ext = Path(filename).suffix.lower()
    if ext in TEXT_EXTENSIONS or format_hint in {"plantuml", "mermaid", "graphviz", "drawio", "text"}:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1", errors="ignore")
        return analyze_diagram(
            workspace_id,
            description=text,
            filename=filename,
            format_hint=format_hint,
            mode=mode,
        )

    # SVG is often XML text — prefer parse before vision
    if ext == ".svg":
        try:
            svg_text = data.decode("utf-8")
        except UnicodeDecodeError:
            svg_text = data.decode("latin-1", errors="ignore")
        if "<svg" in svg_text.lower() or "-->" in svg_text:
            return analyze_diagram(
                workspace_id,
                description=svg_text,
                filename=filename,
                format_hint=format_hint or "text",
                mode=mode,
            )

    vision_meta: dict[str, Any] | None = None
    vision_error: str | None = None
    vision_text: str | None = None
    ocr_meta: dict[str, Any] | None = None
    ocr_error: str | None = None
    ocr_text: str | None = None
    seed_used: str | None = None
    extract_source = "unknown"

    is_raster = ext in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"} or (
        format_hint or ""
    ).lower() in {"image", "png", "jpg", "jpeg", "webp", "gif"}

    if is_raster:
        try:
            from isovane_serve import vision_diagram as vision_diagram_mod

            vision_meta = vision_diagram_mod.extract_diagram_text_from_image(data, filename)
            vision_text = str(vision_meta.get("text") or "").strip() or None
        except Exception as exc:  # noqa: BLE001 — fall back to OCR / seed
            vision_error = str(exc)

    known_seed = seed_for_filename(filename)
    vision_nodes = _count_nodes(vision_text or "")
    vision_edges = _count_edges(vision_text or "")
    # llava often returns 1–2 boxes + one arrow and claims success — treat that as sparse.
    vision_complete = bool(vision_text) and vision_edges > 0 and vision_nodes >= 4
    vision_sparse = bool(vision_text) and vision_edges > 0 and not vision_complete

    if vision_complete:
        description = vision_text or ""
        extract_source = "vision"
    elif vision_sparse and known_seed and _count_nodes(known_seed) > vision_nodes:
        # Partial vision + richer fixture seed → keep full topology; user can still edit.
        description = known_seed
        seed_used = "fixture"
        extract_source = "vision+seed"
    else:
        # Vision failed / sparse without a richer seed → try OCR (labels + heuristic edges).
        if is_raster and not vision_complete:
            try:
                from isovane_serve import ocr_diagram as ocr_diagram_mod

                ocr_meta = ocr_diagram_mod.extract_diagram_text_via_ocr(data, filename)
                ocr_text = str(ocr_meta.get("text") or "").strip() or None
            except Exception as exc:  # noqa: BLE001
                ocr_error = str(exc)

        ocr_nodes = int((ocr_meta or {}).get("label_count") or 0) or _count_nodes(ocr_text or "")
        ocr_edges = _count_edges(ocr_text or "")
        if (
            vision_sparse
            and vision_text
            and vision_nodes >= ocr_nodes
            and (not known_seed or _count_nodes(known_seed) <= vision_nodes)
        ):
            # Best we have is the sparse vision graph (unknown image).
            description = vision_text
            extract_source = "vision"
        elif ocr_text and (ocr_edges > 0 or ocr_nodes >= 2):
            # Keep known fixture topology when OCR cannot see arrows well.
            if known_seed and ocr_edges == 0:
                description = known_seed
                seed_used = "fixture"
                extract_source = "ocr+seed"
            else:
                description = ocr_text
                extract_source = "ocr"
        elif known_seed:
            description = known_seed
            seed_used = "fixture"
            extract_source = "seed"
        elif vision_sparse and vision_text:
            description = vision_text
            extract_source = "vision"
        else:
            description = generic_connected_seed(filename)
            seed_used = "generic"
            extract_source = "seed"

    result = analyze_diagram(
        workspace_id,
        description=description,
        filename=filename,
        format_hint=format_hint or ("vision" if extract_source == "vision" else "image"),
        mode=mode,
    )
    inventory = dict(result.get("inventory") or {})
    board_edges = (inventory.get("board") or {}).get("edges") or inventory.get("edges") or []
    inventory["vision"] = _extract_status(
        extract_source=extract_source,
        vision_meta=vision_meta,
        vision_error=vision_error,
        vision_text=vision_text,
        vision_edges=vision_edges,
        vision_nodes=vision_nodes,
        ocr_meta=ocr_meta,
        ocr_error=ocr_error,
        seed_used=seed_used,
        board_edge_count=len(board_edges),
    )
    result["inventory"] = inventory
    return result


def _extract_status(
    *,
    extract_source: str,
    vision_meta: dict[str, Any] | None,
    vision_error: str | None,
    vision_text: str | None,
    vision_edges: int,
    vision_nodes: int = 0,
    ocr_meta: dict[str, Any] | None,
    ocr_error: str | None,
    seed_used: str | None,
    board_edge_count: int,
) -> dict[str, Any]:
    """User-facing extraction notice: which engine worked / what we fell back to."""
    notice: dict[str, Any] = {
        "source": extract_source,
        "edge_count": board_edge_count,
        "seed": seed_used,
        "vision_nodes": vision_nodes,
        "vision_edges": vision_edges,
    }
    if extract_source == "vision" and vision_meta:
        notice.update(
            {
                "status": "ok",
                "provider": vision_meta.get("provider"),
                "model": vision_meta.get("model"),
                "extracted_chars": len(vision_text or ""),
                "message": "Vision LLM recreated boxes and arrows from the image.",
            }
        )
        return notice

    if extract_source == "vision+seed":
        notice.update(
            {
                "status": "seeded",
                "provider": (vision_meta or {}).get("provider"),
                "model": (vision_meta or {}).get("model"),
                "extracted_chars": len(vision_text or ""),
                "message": (
                    f"Vision only recovered {vision_nodes} box(es) / {vision_edges} arrow(s) — "
                    "loaded the fuller fixture seed so the board is complete. Correct anything off, then Analyze board."
                ),
            }
        )
        return notice

    if vision_error:
        notice["vision_error"] = vision_error
        notice["error"] = vision_error  # legacy field
    elif vision_meta and vision_edges == 0:
        notice["vision_error"] = "Vision returned text but no usable arrows."
    elif vision_meta and vision_nodes and vision_nodes < 4:
        notice["vision_error"] = (
            f"Vision returned a partial board ({vision_nodes} boxes / {vision_edges} arrows)."
        )

    if extract_source in {"ocr", "ocr+seed"} and ocr_meta:
        notice.update(
            {
                "status": "ocr_fallback",
                "provider": "ocr",
                "model": ocr_meta.get("model") or "tesseract",
                "ocr_labels": ocr_meta.get("label_count"),
                "ocr_edges": ocr_meta.get("edge_count"),
                "message": (
                    "Vision LLM failed or had no arrows — fell back to OCR (Tesseract). "
                    + (
                        "Fixture seed kept topology because OCR cannot reliably see arrows."
                        if extract_source == "ocr+seed"
                        else "Correct any missed arrows on the board, then Analyze board."
                    )
                ),
            }
        )
        if ocr_error:
            notice["ocr_error"] = ocr_error
        return notice

    if ocr_error:
        notice["ocr_error"] = ocr_error

    if seed_used:
        notice.update(
            {
                "status": "fallback" if vision_error else "seeded",
                "message": (
                    "Vision LLM failed"
                    + (f" ({vision_error})" if vision_error else "")
                    + (
                        f"; OCR unavailable ({ocr_error}). "
                        if ocr_error
                        else "; OCR had no usable labels. "
                    )
                    + f"Loaded a faithful {seed_used} seed. Correct the board if needed."
                ),
            }
        )
        return notice

    notice.update({"status": "fallback", "message": "Could not extract diagram; used a generic seed."})
    return notice


def _count_edges(text: str) -> int:
    if not text:
        return 0
    parsed = parse_graph_json(text) or {}
    edges = parsed.get("edges") if isinstance(parsed, dict) else None
    if isinstance(edges, list) and edges:
        return len(edges)
    return len(re.findall(r"-->|->|→", text))


def _count_nodes(text: str) -> int:
    if not text:
        return 0
    parsed = parse_graph_json(text) or {}
    nodes = parsed.get("nodes") if isinstance(parsed, dict) else None
    if isinstance(nodes, list) and nodes:
        return len(nodes)
    # NODES: bullet section from vision prompt
    section = re.search(
        r"(?is)NODES:\s*(.*?)(?:TRUST\s*/\s*NOTES:|GRAPH_JSON:|DIAGRAM:|\Z)",
        text,
    )
    if section:
        bullets = re.findall(r"(?m)^\s*[-*•]\s+\S+", section.group(1))
        if bullets:
            return len(bullets)
    # Distinct endpoints from arrow lines
    labels: set[str] = set()
    for left, right in re.findall(
        r"(?m)^\s*([^-\n]+?)\s*(?:-->|->|→)\s*([^:\n]+)",
        text,
    ):
        a, b = left.strip(), right.strip()
        if a:
            labels.add(a.lower())
        if b:
            labels.add(b.lower())
    return len(labels)


def _legacy_trust_rules(
    workspace_id: str, text: str, filename: str | None
) -> list[Finding]:
    lower = text.lower()
    findings: list[Finding] = []
    has_mail = any(token in lower for token in ("gmail", "email", "smtp", "mail", "sendgrid"))
    has_public = any(token in lower for token in ("public", "chat", "internet", "user", "web", "client"))
    has_llm = any(token in lower for token in ("llm", "model", "gpt", "claude", "agent", "openai"))
    if has_public and has_mail and has_llm:
        title = "Untrusted mail path to agent tools"
        summary = "Public/chat → LLM → mail suggests goal hijack / tool misuse."
        owasp = ["ASI01", "ASI02"]
        insight = insight_for(title=title, issue_text=summary, tool="architecture-workflow")
        fields = insight.as_finding_fields(owasp)
        fields["tags"] = list(dict.fromkeys([*(fields.get("tags") or []), "Workflow graph"]))
        suggested = apply_remediation_fields(
            title=title,
            owasp=owasp,
            category="architecture",
            path=filename,
            existing=SuggestedFix(
                kind="architecture",
                summary="Block send when source=email; quarantine inbound mail.",
                checklist=insight.merge_checklist(
                    ["Block send when source=email", "Quarantine inbound mail"]
                ),
            ),
        )
        if suggested.checklist:
            fields["solutions"] = list(suggested.checklist)
        findings.append(
            Finding(
                workspace_id=workspace_id,
                source="analyze",
                severity="high",
                title=title,
                category="architecture",
                evidence=FindingEvidence(
                    path=filename,
                    diagram_region="mail-path",
                    snippet="Public → LLM → mail",
                    tool="architecture-workflow",
                    args={"analysis_mode": "workflow"},
                ),
                suggested_fix=suggested,
                **fields,
            )
        )
    return findings


def _from_plantuml(text: str) -> str:
    """PlantUML → edge list the board/LLM pipeline understands.

    Handles quoted names, `as Alias`, and edge labels (`A --> B : note`).
    """
    alias_to_label: dict[str, str] = {}
    labels: list[str] = []
    edges: list[tuple[str, str]] = []

    elem_re = re.compile(
        r"^(?:component|rectangle|database|actor|participant|cloud|node|package|"
        r"folder|frame|card)\s+"
        r"(?:[\"']([^\"']+)[\"']|([^\s\"'{][^\"'{]*?))"
        r"(?:\s+as\s+(\w+))?"
        r"\s*\{?\s*$",
        re.I,
    )
    edge_re = re.compile(
        r"^[\"']?([^\"'\n]+?)[\"']?\s*(?:-->|->|\.\.>|\.\.-+|-+>)\s*"
        r"[\"']?([^\"'\n:]+?)[\"']?(?:\s*:.*)?$",
        re.I,
    )

    in_note = False
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith(("@", "'", "!")):
            continue
        lower = raw.lower()
        if lower.startswith("note ") or lower.startswith("legend"):
            in_note = True
            continue
        if lower.startswith("end note") or lower.startswith("endlegend") or lower == "end":
            in_note = False
            continue
        if in_note or raw in {"{", "}"} or lower.startswith("skinparam") or lower.startswith("title"):
            continue

        elem = elem_re.match(raw)
        if elem:
            label = _clean_puml_label(elem.group(1) or elem.group(2) or "")
            alias = (elem.group(3) or "").strip()
            if label:
                labels.append(label)
                if alias:
                    alias_to_label[alias] = label
                    alias_to_label[alias.lower()] = label
            continue

        edge = edge_re.match(raw)
        if edge:
            left = _clean_puml_label(edge.group(1))
            right = _clean_puml_label(edge.group(2))
            left = alias_to_label.get(left) or alias_to_label.get(left.lower()) or left
            right = alias_to_label.get(right) or alias_to_label.get(right.lower()) or right
            if left and right and left.lower() != right.lower():
                edges.append((left, right))
                labels.extend([left, right])

    out = [f"{a} --> {b}" for a, b in edges]
    seen = {a.lower() for a, _ in edges} | {b.lower() for _, b in edges}
    for label in labels:
        if label.lower() not in seen:
            out.append(label)
            seen.add(label.lower())
    return "\n".join(out) if out else text


def _clean_puml_label(raw: str) -> str:
    label = re.sub(r"\\n", " ", raw or "")
    return re.sub(r"\s+", " ", label).strip(" `\"'")


def _from_graphviz(text: str) -> str:
    lines: list[str] = []
    for match in re.finditer(r'"?([\w.-]+)"?\s*->\s*"?([\w.-]+)"?', text):
        lines.append(f"{match.group(1)} --> {match.group(2)}")
    for match in re.finditer(r'label\s*=\s*"([^"]+)"', text, re.I):
        lines.append(match.group(1))
    return "\n".join(lines) if lines else text


def _from_drawio(text: str) -> str:
    values = re.findall(r'\bvalue="([^"]+)"', text)
    cleaned = [re.sub(r"<[^>]+>", "", v).strip() for v in values]
    cleaned = [v for v in cleaned if v and v.lower() not in {"", "&nbsp;"}]
    return "\n".join(cleaned) if cleaned else text


def _extract_nodes(text: str) -> list[str]:
    nodes: list[str] = []
    # Do not treat the "--" inside "-->" as its own arrow (that produced "Label -" junk).
    # Do not let \s match newlines (that produced "OpenAI (US) Agent API" across lines).
    for match in re.finditer(r"([A-Za-z][\w ./()+]*?)\s*(?:-->|==>|→|->)", text):
        label = match.group(1).strip(" -")
        if label:
            nodes.append(label)
    for match in re.finditer(r"\[([^\]]+)\]", text):
        nodes.append(match.group(1).strip())
    for match in re.finditer(r'"([^"]+)"', text):
        nodes.append(match.group(1).strip())
    for line in (text or "").splitlines():
        raw = line.strip()
        if not raw or any(tok in raw for tok in ("-->", "->", "==>", "→")):
            continue
        if re.fullmatch(r"[A-Za-z][\w\s./()+-]{1,80}", raw):
            nodes.append(raw)
    return nodes


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for item in findings:
        key = item.title
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out

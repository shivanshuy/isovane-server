"""Optional OCR fallback when vision LLM cannot read an architecture image.

Uses Tesseract via pytesseract when installed. OCR recovers labels well on clean
PNG diagrams; arrows/topology are only heuristically inferred from word boxes.
"""

from __future__ import annotations

import io
import json
import logging
import re
from typing import Any

log = logging.getLogger("isovane.ocr_diagram")


class OcrDiagramError(RuntimeError):
    """OCR engine missing or failed."""


def extract_diagram_text_via_ocr(data: bytes, filename: str) -> dict[str, Any]:
    """Return DIAGRAM/NODES/GRAPH_JSON-ish text from an image via OCR."""
    try:
        from PIL import Image  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise OcrDiagramError("Pillow is required for OCR fallback.") from exc

    try:
        import pytesseract  # type: ignore
        from pytesseract import Output  # type: ignore
    except ImportError as exc:
        raise OcrDiagramError(
            "OCR fallback needs pytesseract (pip/poetry install pytesseract) "
            "and the Tesseract binary on PATH."
        ) from exc

    try:
        image = Image.open(io.BytesIO(data))
        if image.mode not in ("RGB", "L"):
            image = image.convert("RGB")
    except Exception as exc:  # noqa: BLE001
        raise OcrDiagramError(f"Could not open image for OCR: {exc}") from exc

    try:
        data_dict = pytesseract.image_to_data(image, output_type=Output.DICT)
        raw_text = pytesseract.image_to_string(image) or ""
    except Exception as exc:  # noqa: BLE001 — missing tesseract binary, etc.
        raise OcrDiagramError(
            f"Tesseract OCR failed ({exc}). Install Tesseract and ensure it is on PATH."
        ) from exc

    words = _words_from_tesseract(data_dict)
    labels = _cluster_labels(words)
    if not labels:
        # fall back to line-split plain text
        for line in raw_text.splitlines():
            cleaned = _clean(line)
            if cleaned and len(cleaned) >= 2:
                labels.append({"id": _slug(cleaned), "label": cleaned, "kind": _kind(cleaned), "x": 36.0, "y": 36.0 + 96 * len(labels)})

    if not labels:
        raise OcrDiagramError("OCR found no readable labels on the image.")

    edges = _heuristic_edges(labels)
    nodes_payload = [
        {
            "id": item["id"],
            "label": item["label"],
            "kind": item["kind"],
            "x": item.get("x"),
            "y": item.get("y"),
        }
        for item in labels
    ]
    edges_payload = [{"from": e["from"], "to": e["to"], "kind": "link"} for e in edges]
    diagram_lines = [f"{a['label']} --> {b['label']}" for a, b in ((_by_id(labels, e["from"]), _by_id(labels, e["to"])) for e in edges) if a and b]
    if not diagram_lines:
        diagram_lines = [item["label"] for item in labels]

    text = (
        "DIAGRAM:\n"
        + "\n".join(diagram_lines)
        + "\nNODES:\n"
        + "\n".join(f"- {item['label']}" for item in labels)
        + "\nGRAPH_JSON:\n"
        + json.dumps({"nodes": nodes_payload, "edges": edges_payload})
    )
    return {
        "text": text,
        "provider": "ocr",
        "model": "tesseract",
        "filename": filename,
        "label_count": len(labels),
        "edge_count": len(edges_payload),
        "raw_chars": len(raw_text),
    }


def _clean(raw: str) -> str:
    return re.sub(r"\s+", " ", (raw or "").strip())


def _slug(label: str) -> str:
    base = re.sub(r"[^a-zA-Z0-9]+", "_", label).strip("_").lower() or "node"
    return base[:40]


def _kind(label: str) -> str:
    from isovane_serve.kinds import kind_for_label

    return kind_for_label(label)


def _words_from_tesseract(data_dict: dict[str, list[Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    n = len(data_dict.get("text") or [])
    for i in range(n):
        text = _clean(str(data_dict["text"][i] or ""))
        try:
            conf = float(data_dict["conf"][i])
        except (TypeError, ValueError, KeyError):
            conf = -1
        if not text or conf < 40:
            continue
        if len(text) == 1 and text.lower() not in {"a"}:
            continue
        out.append(
            {
                "text": text,
                "left": float(data_dict["left"][i]),
                "top": float(data_dict["top"][i]),
                "width": float(data_dict["width"][i]),
                "height": float(data_dict["height"][i]),
                "line": int(data_dict.get("line_num", [0] * n)[i] or 0),
                "block": int(data_dict.get("block_num", [0] * n)[i] or 0),
            }
        )
    return out


def _cluster_labels(words: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group nearby OCR words on the same line into component labels."""
    if not words:
        return []
    words = sorted(words, key=lambda w: (w["block"], w["line"], w["left"]))
    groups: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    for word in words:
        if not current:
            current = [word]
            continue
        prev = current[-1]
        same_line = word["block"] == prev["block"] and word["line"] == prev["line"]
        gap = word["left"] - (prev["left"] + prev["width"])
        if same_line and gap < max(24.0, prev["width"] * 0.8):
            current.append(word)
        else:
            groups.append(current)
            current = [word]
    if current:
        groups.append(current)

    labels: list[dict[str, Any]] = []
    used: set[str] = set()
    for group in groups:
        label = _clean(" ".join(w["text"] for w in group))
        if len(label) < 2:
            continue
        # skip PlantUML chrome / noise
        if label.lower() in {"org", "vpc", "eu", "us", "title", "note"}:
            continue
        nid = _slug(label)
        base = nid
        n = 2
        while nid in used:
            nid = f"{base}_{n}"
            n += 1
        used.add(nid)
        left = min(w["left"] for w in group)
        top = min(w["top"] for w in group)
        labels.append(
            {
                "id": nid,
                "label": label,
                "kind": _kind(label),
                "x": left,
                "y": top,
            }
        )
    return labels


def _heuristic_edges(labels: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Connect left→right neighbors as a weak topology guess (OCR cannot see arrows)."""
    if len(labels) < 2:
        return []
    ordered = sorted(labels, key=lambda item: (float(item.get("x") or 0), float(item.get("y") or 0)))
    edges: list[dict[str, str]] = []
    # column banding: connect each node to nearest node clearly to its right
    for i, src in enumerate(ordered):
        sx, sy = float(src.get("x") or 0), float(src.get("y") or 0)
        best = None
        best_score = 1e18
        for dst in ordered[i + 1 :]:
            dx = float(dst.get("x") or 0) - sx
            if dx < 40:
                continue
            dy = abs(float(dst.get("y") or 0) - sy)
            if dy > 120:
                continue
            score = dx + dy * 1.5
            if score < best_score:
                best_score = score
                best = dst
        if best:
            edge = {"from": str(src["id"]), "to": str(best["id"])}
            if edge not in edges:
                edges.append(edge)
    return edges[: max(12, len(labels))]


def _by_id(labels: list[dict[str, Any]], nid: str) -> dict[str, Any] | None:
    for item in labels:
        if item["id"] == nid:
            return item
    return None

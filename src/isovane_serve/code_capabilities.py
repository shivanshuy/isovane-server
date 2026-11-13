"""Structural (AST) capabilities for a Python module.

Used to gate promptlint heuristics: HITL / RAG findings require real tool or
retriever wiring in the syntax tree — not English verbs in prompt strings.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from isovane_serve.yaml_config import skip_dir_names


@dataclass
class FileCapabilities:
    has_tool_agency: bool = False
    has_retriever: bool = False
    has_prompt_sink: bool = False
    tool_line: int | None = None
    tool_snippet: str = ""
    retriever_line: int | None = None
    retriever_snippet: str = ""
    reasons: list[str] = field(default_factory=list)


_TOOL_CALL_NAMES = {
    "bind_tools",
    "create_react_agent",
    "ToolNode",
    "ToolExecutor",
    "StructuredTool",
    "send_email",
    "pay_refund",
    "run_shell",
    "execute_command",
}
_TOOL_ATTRS = {"bind_tools", "invoke", "ainvoke"}
_RETRIEVER_CALL_NAMES = {
    "similarity_search",
    "similarity_search_with_score",
    "as_retriever",
    "from_documents",
    "from_texts",
    "max_marginal_relevance_search",
    "get_relevant_documents",
}
_RETRIEVER_NAME_HINTS = (
    "retriever",
    "vectorstore",
    "vector_store",
    "chroma",
    "chromadb",
    "pinecone",
    "faiss",
    "docstore",
    "knowledge_base",
)
_PROMPT_SINKS = {
    "SystemMessage",
    "ChatPromptTemplate",
    "PromptTemplate",
    "SystemMessagePromptTemplate",
    "HumanMessage",
    "AIMessage",
}


_TOOL_REGEX = re.compile(
    r"(?m)(@tool\b|\bbind_tools\s*\(|\bcreate_react_agent\s*\(|\bToolNode\s*\(|"
    r"\btools\s*=\s*\[|\bsend_email\b|\bpay_refund\b|\brun_shell\b|"
    r"\bshell\s*=\s*True\b|\bos\.system\s*\(|\bsubprocess\.(?:run|Popen|call)\s*\()"
)
_RETRIEVER_REGEX = re.compile(
    r"(?m)(\bas_retriever\s*\(|\bsimilarity_search(?:_with_score)?\s*\(|"
    r"\bget_relevant_documents\s*\(|\bmax_marginal_relevance_search\s*\(|"
    r"\bChroma\s*\(|\bPinecone\s*\(|\bFAISS\s*\(|\bfrom_documents\s*\()"
)


def probe_python_source(source: str) -> FileCapabilities:
    caps = FileCapabilities()
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # Incomplete / mixed uploads — still detect wiring via syntax regex.
        return _probe_regex(source, lines)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            qual = _call_qualname(node.func).lower()
            lineno = getattr(node, "lineno", None)
            snippet = _window(lines, lineno)

            if name in _TOOL_CALL_NAMES or name == "bind_tools" or ".bind_tools" in f".{qual}":
                _mark_tool(caps, lineno, snippet, f"call:{name or qual}")
            if name in {"ToolNode", "create_react_agent"}:
                _mark_tool(caps, lineno, snippet, f"call:{name}")
            # tools=[...] keyword on agent constructors
            for kw in node.keywords:
                if kw.arg == "tools":
                    _mark_tool(caps, lineno, snippet, "kw:tools")
            # retriever / vector calls
            if name in _RETRIEVER_CALL_NAMES or any(h in qual for h in _RETRIEVER_NAME_HINTS):
                # avoid marking every .invoke as retriever — require retriever-ish qualifier/name
                if name in _RETRIEVER_CALL_NAMES or any(
                    h in qual for h in ("retriev", "vector", "chroma", "pinecone", "faiss", "docstore")
                ):
                    _mark_retriever(caps, lineno, snippet, f"call:{name or qual}")
            if name in _PROMPT_SINKS:
                caps.has_prompt_sink = True

        elif isinstance(node, ast.FunctionDef):
            # @tool decorator
            for dec in node.decorator_list:
                dec_name = _call_name(dec) if isinstance(dec, ast.Call) else (
                    dec.id if isinstance(dec, ast.Name) else (
                        dec.attr if isinstance(dec, ast.Attribute) else ""
                    )
                )
                if dec_name == "tool":
                    _mark_tool(
                        caps,
                        getattr(node, "lineno", None),
                        _window(lines, getattr(node, "lineno", None)),
                        "@tool",
                    )

        elif isinstance(node, ast.Assign):
            for target in node.targets:
                for tname in _target_names(target):
                    low = tname.lower()
                    if low in {"tools", "tool_list"} or low.endswith("_tools"):
                        _mark_tool(
                            caps,
                            getattr(node, "lineno", None),
                            _window(lines, getattr(node, "lineno", None)),
                            f"assign:{tname}",
                        )
                    if any(h in low for h in _RETRIEVER_NAME_HINTS):
                        _mark_retriever(
                            caps,
                            getattr(node, "lineno", None),
                            _window(lines, getattr(node, "lineno", None)),
                            f"assign:{tname}",
                        )

    # Regex backstop for patterns AST walked but missed (dynamic attrs, etc.)
    if not caps.has_tool_agency or not caps.has_retriever:
        regex_caps = _probe_regex(source, lines)
        if not caps.has_tool_agency and regex_caps.has_tool_agency:
            caps.has_tool_agency = True
            caps.tool_line = regex_caps.tool_line
            caps.tool_snippet = regex_caps.tool_snippet
            caps.reasons.extend(regex_caps.reasons)
        if not caps.has_retriever and regex_caps.has_retriever:
            caps.has_retriever = True
            caps.retriever_line = regex_caps.retriever_line
            caps.retriever_snippet = regex_caps.retriever_snippet
            caps.reasons.extend(regex_caps.reasons)

    return caps


def _probe_regex(source: str, lines: list[str]) -> FileCapabilities:
    caps = FileCapabilities()
    for match in _TOOL_REGEX.finditer(source):
        lineno = source[: match.start()].count("\n") + 1
        _mark_tool(caps, lineno, _window(lines, lineno), f"re:{match.group(0)[:40]}")
    for match in _RETRIEVER_REGEX.finditer(source):
        lineno = source[: match.start()].count("\n") + 1
        _mark_retriever(caps, lineno, _window(lines, lineno), f"re:{match.group(0)[:40]}")
    return caps


def probe_python_path(path: Path) -> FileCapabilities:
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return FileCapabilities()
    return probe_python_source(source)


def probe_tree(root: Path) -> dict[str, FileCapabilities]:
    """Map repo-relative posix paths → capabilities."""
    out: dict[str, FileCapabilities] = {}
    if not root.exists():
        return out
    for path in root.rglob("*.py"):
        if any(part in skip_dir_names() for part in path.parts):
            continue
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.as_posix()
        out[rel] = probe_python_path(path)
        # also index with backslash form for Windows callers
        out[rel.replace("/", "\\")] = out[rel]
    return out


def _mark_tool(caps: FileCapabilities, lineno: int | None, snippet: str, reason: str) -> None:
    caps.has_tool_agency = True
    if reason not in caps.reasons:
        caps.reasons.append(reason)
    if caps.tool_line is None and lineno:
        caps.tool_line = lineno
        caps.tool_snippet = snippet


def _mark_retriever(
    caps: FileCapabilities, lineno: int | None, snippet: str, reason: str
) -> None:
    caps.has_retriever = True
    if reason not in caps.reasons:
        caps.reasons.append(reason)
    if caps.retriever_line is None and lineno:
        caps.retriever_line = lineno
        caps.retriever_snippet = snippet


def _line(lines: list[str], lineno: int | None) -> str:
    if not lineno or lineno < 1 or lineno > len(lines):
        return ""
    return lines[lineno - 1].strip()[:240]


def _window(lines: list[str], lineno: int | None, *, radius: int = 5) -> str:
    """Multi-line source window so Technical details is readable (not one orphan line)."""
    if not lineno or lineno < 1 or lineno > len(lines):
        return ""
    lo = max(0, lineno - 1 - radius)
    hi = min(len(lines), lineno + radius)
    return "\n".join(lines[lo:hi])[:1200]


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Call):
        return _call_name(func.func)
    return ""


def _call_qualname(func: ast.AST) -> str:
    parts: list[str] = []
    cur: ast.AST | None = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    parts.reverse()
    return ".".join(parts)


def _target_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for elt in target.elts:
            names.extend(_target_names(elt))
        return names
    return []

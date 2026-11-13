"""Python AST taint: untrusted sources → system prompts / consequential tools.

Tracks simple aliases and assignment kills for better precision than name-only
heuristics (LLMArmor-inspired source/sink catalog, intra-procedural).
"""

from __future__ import annotations

import ast
from pathlib import Path

from isovane_serve.insights import insight_for
from isovane_serve.models import Finding, FindingEvidence, SuggestedFix
from isovane_serve.yaml_config import load_scan_settings, skip_dir_names


def _ast_cfg() -> dict:
    return load_scan_settings()["ast_taint"]


def scan_ast_taint(workspace_id: str, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not root.exists():
        return findings
    for path in root.rglob("*.py"):
        if any(part in skip_dir_names() for part in path.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        findings.extend(_analyze_module(workspace_id, rel, source, tree))
    return findings


def _analyze_module(
    workspace_id: str, rel: str, source: str, tree: ast.AST
) -> list[Finding]:
    out: list[Finding] = []
    lines = source.splitlines()

    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.extend(_analyze_function(workspace_id, rel, lines, node))
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out.extend(_analyze_function(workspace_id, rel, lines, item))

    # Module-level snippets (scripts without defs)
    if isinstance(tree, ast.Module):
        tainted = set()
        out.extend(
            _walk_statements(workspace_id, rel, lines, list(tree.body), tainted, module=True)
        )
    return _dedupe(out)


def _analyze_function(
    workspace_id: str,
    rel: str,
    lines: list[str],
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[Finding]:
    tainted: set[str] = set()
    for arg in list(fn.args.posonlyargs) + list(fn.args.args) + list(fn.args.kwonlyargs):
        if _is_userish(arg.arg):
            tainted.add(arg.arg)
    if fn.args.vararg and _is_userish(fn.args.vararg.arg):
        tainted.add(fn.args.vararg.arg)
    if fn.args.kwarg and _is_userish(fn.args.kwarg.arg):
        tainted.add(fn.args.kwarg.arg)
    return _walk_statements(workspace_id, rel, lines, list(fn.body), tainted, module=False)


def _walk_statements(
    workspace_id: str,
    rel: str,
    lines: list[str],
    stmts: list[ast.stmt],
    tainted: set[str],
    *,
    module: bool,
) -> list[Finding]:
    out: list[Finding] = []
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Nested defs handled separately when module=True via _analyze_module;
            # when inside a function, analyze nested too.
            if not module and isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.extend(_analyze_function(workspace_id, rel, lines, stmt))
            continue
        if isinstance(stmt, ast.Assign):
            _apply_assign(stmt.targets, stmt.value, tainted)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None and stmt.target:
            _apply_assign([stmt.target], stmt.value, tainted)
        elif isinstance(stmt, ast.AugAssign):
            if isinstance(stmt.target, ast.Name) and (
                _expr_tainted(stmt.value, tainted) or stmt.target.id in tainted
            ):
                tainted.add(stmt.target.id)
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            out.extend(_check_call(workspace_id, rel, lines, stmt.value, tainted))
        elif isinstance(stmt, ast.Return) and stmt.value is not None:
            # returning SystemMessage(...) etc.
            if isinstance(stmt.value, ast.Call):
                out.extend(_check_call(workspace_id, rel, lines, stmt.value, tainted))
        # Dive into if/for/with bodies with same tainted set (flow-insensitive union)
        for child_body in _branch_bodies(stmt):
            out.extend(
                _walk_statements(
                    workspace_id, rel, lines, child_body, tainted, module=False
                )
            )
        # Also scan calls nested anywhere in statement
        for call in _iter_calls(stmt):
            out.extend(_check_call(workspace_id, rel, lines, call, tainted))
    return out


def _branch_bodies(stmt: ast.stmt) -> list[list[ast.stmt]]:
    bodies: list[list[ast.stmt]] = []
    if isinstance(stmt, ast.If):
        bodies.append(list(stmt.body))
        bodies.append(list(stmt.orelse))
    elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
        bodies.append(list(stmt.body))
        bodies.append(list(stmt.orelse))
    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        bodies.append(list(stmt.body))
    elif isinstance(stmt, ast.Try):
        bodies.append(list(stmt.body))
        for h in stmt.handlers:
            bodies.append(list(h.body))
        bodies.append(list(stmt.orelse))
        bodies.append(list(stmt.finalbody))
    return bodies


def _iter_calls(node: ast.AST) -> list[ast.Call]:
    return [n for n in ast.walk(node) if isinstance(n, ast.Call)]


def _apply_assign(targets: list[ast.expr], value: ast.expr, tainted: set[str]) -> None:
    is_t = _expr_tainted(value, tainted) or _is_source_expr(value)
    is_clean = _is_clean_literal(value)
    for target in targets:
        names = _target_names(target)
        for name in names:
            if is_t:
                tainted.add(name)
            elif is_clean:
                tainted.discard(name)


def _target_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for elt in target.elts:
            names.extend(_target_names(elt))
        return names
    return []


def _is_userish(name: str) -> bool:
    n = name.lower()
    if n in _ast_cfg()["userish_names"]:
        return True
    return n.endswith(("_input", "_text", "_msg", "_message", "_query", "_prompt"))


def _is_clean_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        # f-string with only constant parts
        return all(
            isinstance(v, ast.Constant)
            or (isinstance(v, ast.FormattedValue) and _is_clean_literal(v.value))
            for v in node.values
        )
    return False


def _is_source_expr(node: ast.AST) -> bool:
    cfg = _ast_cfg()
    if isinstance(node, ast.Call):
        name = _call_name(node.func)
        if name in cfg["source_calls"]:
            return True
        # request.json(), request.get_json()
        if name in {"json", "get_json", "get_data", "form"} and _attr_root_is_request(
            node.func
        ):
            return True
        if name == "get" and (
            _attr_root_is_request(node.func)
            or _expr_is_request_attr(node.func if isinstance(node.func, ast.Attribute) else None)
        ):
            return True
        if name in {"recv", "receive", "receive_text", "receive_json"}:
            return True
    if isinstance(node, ast.Attribute):
        if node.attr in cfg["request_attrs"] and _attr_root_name(node) in cfg["request_roots"]:
            return True
        if isinstance(node.value, ast.Name) and node.value.id == "sys" and node.attr == "argv":
            return True
    if isinstance(node, ast.Subscript):
        return _is_source_expr(node.value) or _expr_is_request_attr(node.value)
    return False


def _attr_root_name(node: ast.AST) -> str | None:
    cur = node
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    if isinstance(cur, ast.Name):
        return cur.id
    if isinstance(cur, ast.Call):
        return _attr_root_name(cur.func)
    return None


def _attr_root_is_request(func: ast.AST) -> bool:
    if isinstance(func, ast.Attribute):
        return _attr_root_name(func) in _ast_cfg()["request_roots"]
    return False


def _expr_is_request_attr(node: ast.AST | None) -> bool:
    if node is None:
        return False
    cfg = _ast_cfg()
    if isinstance(node, ast.Attribute):
        return node.attr in cfg["request_attrs"] and _attr_root_name(node) in cfg["request_roots"]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return _expr_is_request_attr(node.func)
    return False


def _expr_tainted(node: ast.AST | None, tainted: set[str]) -> bool:
    if node is None:
        return False
    if _is_source_expr(node):
        return True
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.Attribute):
        cfg = _ast_cfg()
        roots = tainted | cfg["request_roots"]
        if node.attr.lower() in cfg["userish_names"] and _attr_root_name(node) in roots:
            return True
        return _expr_tainted(node.value, tainted)
    if isinstance(node, ast.Subscript):
        return _expr_tainted(node.value, tainted)
    if isinstance(node, ast.JoinedStr):
        return any(
            _expr_tainted(v.value, tainted)
            for v in node.values
            if isinstance(v, ast.FormattedValue)
        )
    if isinstance(node, ast.FormattedValue):
        return _expr_tainted(node.value, tainted)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _expr_tainted(node.left, tainted) or _expr_tainted(node.right, tainted)
    if isinstance(node, ast.Call):
        name = _call_name(node.func)
        if name in {"format", "join"}:
            if any(_expr_tainted(a, tainted) for a in node.args):
                return True
            if isinstance(node.func, ast.Attribute) and _expr_tainted(
                node.func.value, tainted
            ):
                return True
        return any(_expr_tainted(a, tainted) for a in node.args) or any(
            _expr_tainted(kw.value, tainted) for kw in node.keywords
        )
    if isinstance(node, ast.IfExp):
        return _expr_tainted(node.body, tainted) or _expr_tainted(node.orelse, tainted)
    return False


def _check_call(
    workspace_id: str,
    rel: str,
    lines: list[str],
    node: ast.Call,
    tainted: set[str],
) -> list[Finding]:
    out: list[Finding] = []
    name = _call_name(node.func)
    full = _call_qualname(node.func)

    cfg = _ast_cfg()
    if name in cfg["prompt_sinks"] or full.endswith(".SystemMessage"):
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            if _expr_tainted(arg, tainted):
                out.append(
                    _hit(
                        workspace_id,
                        rel,
                        node.lineno,
                        lines,
                        title="User-tainted value reaches system prompt constructor",
                        summary=(
                            f"`{name}` takes user-controlled content (LLM01). "
                            "Keep system text static; pass user text as HumanMessage."
                        ),
                        rule_id="ast-taint-prompt",
                    )
                )
                break
        return out

    # Consequential tool sinks — exclude generic langchain `.run` unless shell keyword
    toolish = name.lower() in cfg["tool_sinks"] or name.lower() in {
        "send_email",
        "sendmail",
    }
    if name == "run":
        # subprocess.run(..., shell=True) with tainted args — handled loosely
        shell_kw = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )
        if not shell_kw and full not in {"subprocess.run", "os.system"}:
            toolish = False
    if name in {"exec", "system"} or full in {"os.system", "os.popen", "subprocess.call"}:
        toolish = True

    if toolish:
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            if _expr_tainted(arg, tainted):
                out.append(
                    _hit(
                        workspace_id,
                        rel,
                        node.lineno,
                        lines,
                        title="User-tainted value reaches consequential tool args",
                        summary=(
                            f"Call `{name}` may pass user-controlled data into a "
                            "consequential tool (LLM06 / ASI02). Gate + redact."
                        ),
                        severity="high",
                        rule_id="ast-taint-tool",
                    )
                )
                break
    return out


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
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


def _hit(
    workspace_id: str,
    rel: str,
    lineno: int,
    lines: list[str],
    *,
    title: str,
    summary: str,
    severity: str = "high",
    rule_id: str = "ast-taint",
) -> Finding:
    if 0 < lineno <= len(lines):
        lo = max(0, lineno - 1 - 5)
        hi = min(len(lines), lineno + 5)
        snippet = "\n".join(lines[lo:hi])[:1200]
    else:
        snippet = ""
    insight = insight_for(title=title, issue_text=summary, tool="ast-taint", snippet=snippet)
    return Finding(
        workspace_id=workspace_id,
        source="analyze",
        severity=severity,  # type: ignore[arg-type]
        title=title,
        summary=summary,
        category="prompt" if "system prompt" in title.lower() else "agency",
        owasp=["LLM01"] if "system prompt" in title.lower() else ["LLM06", "ASI02"],
        evidence=FindingEvidence(
            tool="ast-taint",
            path=rel,
            line=lineno,
            snippet=snippet,
            args={"rule_id": rule_id},
        ),
        suggested_fix=SuggestedFix(
            kind="prompt" if "system prompt" in title.lower() else "code",
            summary=summary,
            checklist=[
                "Do not interpolate user input into system prompts",
                "Pass user content as HumanMessage / separate variable",
                "Gate consequential tools with HITL + allow-list",
            ],
            diff=(
                "- SystemMessage(content=f\"You are helpful. User said: {user_text}\")\n"
                "+ SystemMessage(content=\"You are helpful.\")\n"
                "+ HumanMessage(content=user_text)\n"
            ),
        ),
        exploit=insight.exploit or None,
        technical_details=insight.technical_details or None,
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for item in findings:
        line = item.evidence.line if item.evidence else None
        key = f"{item.title}|{item.evidence.path if item.evidence else ''}|{line}"
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out

"""purragent_core.tools — extracted from monolithic purragent.py (Phase A refactor)."""

import mcp_client
import shutil
import tool_retriever

from purragent_core._shared import (_TOOL_AVAIL_CACHE)

def _tool_arg_preview(args: dict) -> str:
    """A short single-line preview of a tool call's main argument (the command,
    path, url, …) — shown after the tool name on the concise activity line."""
    if not isinstance(args, dict) or not args:
        return ""
    # pattern before path so grep previews the regex, not its search dir
    for key in ("command", "url", "pattern", "path", "query"):
        val = args.get(key)
        if val:
            return " ".join(str(val).split())
    return " ".join(str(next(iter(args.values()))).split())



def _tool_status(result: dict) -> tuple:
    """Reliable (no-heuristic) status for a finished tool call → (glyph, style,
    label). Uses only the call-level error flag and run_command's structured
    'exit code:' line; anything else degrades to a plain ok/failed."""
    text = (result.get("text") or "").strip()
    first = text.split("\n", 1)[0].strip()
    if first.startswith("exit code:"):
        rest = first[len("exit code:"):].strip()
        if rest.startswith("(timeout"):
            return "⏱", "yellow", "timed out"
        if rest == "0":
            return "✓", "green", "ok"
        return "✗", "red", f"exit {rest}"
    if result.get("is_error"):
        return "✗", "red", "failed"
    return "✓", "green", "ok"



def _tool_available(t: dict) -> bool:
    """True if the tool can actually run on this host — native/built-in (no program
    needed), or its required program is on PATH and its python libs are present. Used to
    keep uninstallable tools OUT of what the model is offered, so it never wastes an
    LLM call on a tool that can only return '[not installed]'. (Hack mode's deterministic
    phase-5 walk still prints [skipped] for missing tools so the user sees them.)"""
    if t.get("py_missing"):
        return False
    binary = t.get("requires")
    if not binary:
        return True
    ok = _TOOL_AVAIL_CACHE.get(binary)
    if ok is None:
        ok = bool(shutil.which(binary))
        _TOOL_AVAIL_CACHE[binary] = ok
    return ok



def _catalog_signature(tool: dict) -> str:
    """`write_file(path, content, [append])` — the tool's bare name plus its
    parameter list, required params bare and optional ones in [brackets], read
    from the OpenAI schema. Used only for built-ins, which the model calls
    directly by name (so it needs the argument names up front)."""
    bare = mcp_client.split_namespaced(tool["name"])[1]
    params = (tool.get("schema", {}).get("function", {})
              .get("parameters", {}) or {})
    props = list((params.get("properties") or {}).keys())
    required = set(params.get("required") or [])
    rendered = ", ".join(p if p in required else f"[{p}]" for p in props)
    return f"{bare}({rendered})"



def _catalog_block(all_tools: list) -> str:
    """The always-visible capability catalog, split into two sections:

    - built-in: `name(params) — description`, so the model can call these
      directly by their exact name (they never pass through request_tool);
    - others: `- description` only, reached via request_tool, which surfaces
      their full schema on demand.

    Only names + one-line descriptions are sent here — never full schemas — so
    the context stays small even though the model can act on any tool."""
    builtin = [t for t in all_tools if t.get("builtin")]
    others = [t for t in all_tools if not t.get("builtin")]
    blocks = []
    if builtin:
        rows = "\n".join(f"- {_catalog_signature(t)} — {t['short']}"
                         for t in builtin)
        blocks.append("built-in (call these directly by their exact name):\n"
                      + rows)
    if others:
        rows = "\n".join(f"- {t['short']}" for t in others)
        blocks.append("others (call request_tool to obtain one of these):\n"
                      + rows)
    return "<tool_catalog>\n" + "\n\n".join(blocks) + "\n</tool_catalog>"



def _resolve_tool_name(name: str, all_tools: list):
    """Map a loose/fabricated tool reference to a real namespaced tool name, or
    None. Matches (case-insensitively) the exact namespaced name, the bare tool
    name, or the tool's short catalog description — covering models that ignore
    request_tool and call a tool by its description or without the namespace."""
    if not name:
        return None
    key = name.strip().lower().rstrip(".")
    for t in all_tools:
        full = t["name"]
        bare = mcp_client.split_namespaced(full)[1]
        short = (t.get("short") or "").strip().lower().rstrip(".")
        if key in (full.lower(), bare.lower(), short):
            return full
    return None



_TOOL_RETRIEVER = None



def _get_retriever(base_dir: str, all_tools: list):
    """Lazily build/refresh the shared tool retriever. Returns it, or None if
    embeddings are unavailable (caller then falls back to sending all schemas)."""
    global _TOOL_RETRIEVER
    try:
        if _TOOL_RETRIEVER is None:
            _TOOL_RETRIEVER = tool_retriever.ToolRetriever(base_dir)
        if _TOOL_RETRIEVER.build(all_tools):
            return _TOOL_RETRIEVER
    except Exception:
        return None
    return None


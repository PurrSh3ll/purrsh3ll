"""purragent_core.models — extracted from monolithic purragent.py (Phase A refactor)."""

import functools
import getpass
import json
import os
import platform
import psai

from purragent_core._shared import (FILL_FRAC, FINDINGS_CAP_FRAC, FINDINGS_FLOOR_TOKENS, MEMORY_LOOKUP_TOKENS, OUTPUT_FLOOR, PLAN_MODE_NOTE, PURRAGENT_SYSTEM, SUMMARIZED_CAP_FRAC, TOOLS_RESERVATION_TOKENS, _DISCOVERY_GUIDE, _LOCAL_CTX_PROVIDERS)
from purragent_core.state import (_findings_block, _memory_block)
from purragent_core.tools import (_catalog_block, _tool_available)

def _profiles(config: dict) -> list:
    return config.get("api_providers", {}).get("profiles", []) or []



def _find_profile(config: dict, name: str) -> dict | None:
    for p in _profiles(config):
        if p.get("name") == name:
            return p
    return None



def _model_short(profile: dict) -> str:
    """Human-friendly model name for the status line (basename after last '/')."""
    m = profile.get("model", "") or "?"
    if m.lower().startswith("models/"):
        m = m[7:]
    return m.rsplit("/", 1)[-1]



def _is_root() -> bool:
    """True if the process is running with root privileges."""
    try:
        return os.geteuid() == 0
    except AttributeError:      # non-POSIX
        return False



def _model_has_tools(profile: dict, base_dir: str) -> bool:
    """Whether this model supports function calling per the app's registry
    (model_ctx_registry.json) — the capability itself, independent of the profile's
    own tools_user_override. Reuses psai's registry logic with the override stripped."""
    p = dict(profile)
    p.pop("tools_user_override", None)
    try:
        return bool(psai._tools_enabled(p, base_dir))
    except Exception:
        return False



@functools.lru_cache(maxsize=1)
def _load_registry(base_dir: str) -> dict:
    """Cached model_ctx_registry.json (read once — the toolbar checks caps often)."""
    try:
        with open(os.path.join(base_dir, "appdata", "model_ctx_registry.json"),
                  encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}



def _model_capability(profile: dict, base_dir: str, cap: str) -> bool:
    """Whether the model supports `cap` ('vision' or 'audio'). Mirrors the tools
    logic: a per-profile <cap>_user_override wins; otherwise the provider's list
    of capable models in the registry decides."""
    override = profile.get(f"{cap}_user_override")
    if override is not None:
        return bool(override)
    model = profile.get("model", "")
    if model.lower().startswith("models/"):     # Gemini prefix
        model = model[7:]
    if ":" in model:                            # OpenRouter :free / :variant suffix
        model = model.split(":")[0]
    section = _load_registry(base_dir).get(profile.get("provider", "").lower(), {})
    return model.lower() in [m.lower() for m in (section.get(cap) or [])]



def _model_context(profile: dict, base_dir: str):
    """The model's context window (tokens), resolved exactly like the rest of the
    app: explicit profile `context_tokens` override → model_ctx_registry.json
    (exact then prefix match, then provider default via psai) → a provider-based
    fallback (local host 4096, cloud 200k). Only None when there is no profile,
    so — like the GUI — an unknown model still shows a sensible number."""
    if not profile:
        return None
    try:
        val = psai._get_ctx_window(profile, base_dir)
    except Exception:
        val = None
    if val:
        return val
    provider = (profile.get("provider", "") or "").lower()
    return 4096 if provider in _LOCAL_CTX_PROVIDERS else 200_000



def _effective_max_context(ctx: dict, base_dir: str):
    """Session override if set, else the model's registry context size."""
    return ctx.get("max_context") or _model_context(ctx.get("profile"), base_dir)



def _fmt_ctx(n) -> str:
    if not n:
        return "?"
    return f"{round(n / 1000)}k" if n >= 1000 else str(n)



def _parse_ctx_number(s: str):
    """Parse '32000', '32k', '128k', '1m' → int tokens, or None if invalid."""
    s = (s or "").strip().lower().replace(",", "").replace("_", "")
    if not s:
        return None
    mult = 1
    if s.endswith("k"):
        mult, s = 1000, s[:-1]
    elif s.endswith("m"):
        mult, s = 1_000_000, s[:-1]
    try:
        val = int(float(s) * mult)
    except ValueError:
        return None
    return val if val > 0 else None



def _estimate_context_tokens(profile: dict, base_dir: str, history: list,
                             mcp, use_tools: bool) -> int:
    """Rough token estimate (~4 chars/token) of what a prompt now sends: the
    system prompt (+ <env>, + discovery guide & tool catalog when tools are on),
    the whole conversation history and the `tools` request field. An estimate, not
    an exact tokenizer — used to block a request that would blow the window."""
    parts = [PURRAGENT_SYSTEM, _env_block()]
    tools_tok = 0
    if use_tools and mcp is not None:
        try:
            all_tools = mcp.all_tools()
        except Exception:
            all_tools = []
        if all_tools:
            parts += [_DISCOVERY_GUIDE, _catalog_block(all_tools)]
            tools_tok = TOOLS_RESERVATION_TOKENS   # the `tools` request field
    custom = (profile.get("custom_system", "") or "").strip() if profile else ""
    if custom:
        parts.append(custom)
    for m in history:
        c = m.get("content")
        if isinstance(c, str) and c:
            parts.append(c)
    total_chars = sum(len(p) for p in parts)
    return total_chars // 4 + tools_tok



def _fixed_header_parts(profile: dict, base_dir: str, mcp, mode: str) -> list:
    """The fixed per-prompt overhead as [(label, chars)] — system prompt+env, tool
    catalog, custom instructions, saved /memory, and the tools-field reservation. Shared
    by /context (display) and the conversation-budget math so they can't drift."""
    planning = (mode == "plan")
    use_tools = (not planning) and _supports_tool_loop(profile) \
        and _model_has_tools(profile, base_dir)
    sys_chars = len(PURRAGENT_SYSTEM) + len(_env_block())
    if planning:
        sys_chars += len(PLAN_MODE_NOTE)
    cat_chars = tools_chars = 0
    if use_tools and mcp is not None:
        try:
            all_tools = [t for t in mcp.all_tools() if _tool_available(t)]
        except Exception:                              # noqa: BLE001
            all_tools = []
        if all_tools:
            cat_chars = len(_DISCOVERY_GUIDE) + len(_catalog_block(all_tools))
            tools_chars = TOOLS_RESERVATION_TOKENS * 4
    return [
        ("system prompt&env",     sys_chars),
        ("tool catalog",          cat_chars),
        ("custom instructions",   len((profile.get("custom_system", "") or "").strip())),
        ("user memory (/memory)", len(_memory_block(base_dir))),
        ("mcp tools (reserved)",  tools_chars),
    ]



def _conv_budget(profile: dict, base_dir: str, ctx: dict, mcp, mode: str):
    """(avail_chars, recent_target_chars, summ_cap_chars) using the EXACT split /context
    shows. None when the model window is unknown (→ no enforcement).
      • avail          = the whole conversation pool (recent may borrow all of it while
                         nothing is summarised — matches the /debug 'borrow' column);
      • recent_target  = avail − summary cap = where recent is trimmed to once it spills;
      • summ_cap       = the summary slot ceiling."""
    maxc = _effective_max_context(ctx, base_dir)
    if not maxc:
        return None
    budget_tok = max(0, min(int(maxc * FILL_FRAC), maxc - OUTPUT_FLOOR))
    fixed_chars = sum(c for _, c in _fixed_header_parts(profile, base_dir, mcp, mode))
    memory_chars = MEMORY_LOOKUP_TOKENS * 4
    pool = max(0, budget_tok * 4 - fixed_chars - memory_chars)
    findings_demand = len(_findings_block(base_dir))    # recorded findings injected each turn
    findings_chars = min(max(findings_demand, FINDINGS_FLOOR_TOKENS * 4),
                         int(FINDINGS_CAP_FRAC * pool))
    avail = max(0, pool - findings_chars)
    summ_cap = int(SUMMARIZED_CAP_FRAC * pool)
    return avail, max(0, avail - summ_cap), summ_cap



@functools.lru_cache(maxsize=1)
def _env_facts() -> str:
    """Static host facts, computed once per process (re-exec by /upgrade refreshes)."""
    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER", "?")
    try:
        uid = os.geteuid()
        uid_s = f"uid {uid}, {'root' if uid == 0 else 'non-root'}"
    except AttributeError:              # non-POSIX
        uid_s = "non-POSIX"

    distro = ""
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    distro = line.split("=", 1)[1].strip().strip('"')
                    break
    except Exception:
        pass
    kernel = f"{platform.system()} {platform.release()} {platform.machine()}".strip()
    os_line = f"{distro} · {kernel}" if distro else kernel

    return "\n".join([
        f"user: {user} ({uid_s})",
        f"host: {platform.node() or '?'}",
        f"home: {os.path.expanduser('~')}",
        f"os: {os_line}",
        f"shell: {os.environ.get('SHELL', '?')}",
    ])



def _netmask_to_cidr(mask: str) -> int:
    """Dotted-quad netmask → prefix length (255.255.255.0 → 24)."""
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except Exception:
        return 0



def _default_route() -> tuple:
    """(iface, gateway_ip) for the IPv4 default route on Linux via /proc/net/route,
    or ('', '') if it can't be read."""
    try:
        with open("/proc/net/route", encoding="utf-8") as f:
            next(f)                                    # skip the header row
            for line in f:
                cols = line.split()
                if len(cols) >= 3 and cols[1] == "00000000":   # destination 0.0.0.0
                    gw = ".".join(str(int(cols[2][i:i + 2], 16))
                                  for i in (6, 4, 2, 0))        # little-endian hex
                    return cols[0], gw
    except Exception:
        pass
    return "", ""



def _net_facts() -> str:
    """Live network view: each up, non-loopback interface's IPv4 as address/CIDR,
    the default-route interface marked, plus the default gateway. Best-effort via
    psutil; returns '' if unavailable so the <env> block simply omits it."""
    try:
        import socket
        import psutil
    except Exception:
        return ""
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception:
        return ""
    default_if, gateway = _default_route()
    lines = []
    for name in sorted(addrs):
        if name == "lo":
            continue
        st = stats.get(name)
        if st is not None and not st.isup:             # skip down interfaces
            continue
        for a in addrs[name]:
            if (a.family == socket.AF_INET and a.address
                    and not a.address.startswith("127.")):
                cidr = _netmask_to_cidr(a.netmask or "")
                ip = f"{a.address}/{cidr}" if cidr else a.address
                mark = "  (default)" if name == default_if else ""
                lines.append(f"  {name}: {ip}{mark}")
                break                                  # one IPv4 per interface is enough
    if not lines:
        return ""
    out = ["network:"] + lines
    if gateway:
        out.append(f"  gateway: {gateway}")
    return "\n".join(out)



def _env_block() -> str:
    """The <env> block for the system prompt: cached static facts, a live cwd/date
    (so long sessions don't show a stale date), and the live network view (VPNs /
    DHCP leases can change mid-session, so it's recomputed each prompt)."""
    from datetime import date
    parts = ["<env>", _env_facts(),
             f"cwd: {os.getcwd()}", f"date: {date.today().isoformat()}"]
    net = _net_facts()
    if net:
        parts.append(net)
    parts.append("</env>")
    return "\n".join(parts)



def _supports_tool_loop(profile: dict) -> bool:
    """The tool loop speaks two wire formats: OpenAI /chat/completions for the
    OpenAI-compatible providers, and Anthropic /v1/messages for the anthropic
    provider (the OpenAI-shaped transcript is converted at the wire in _chat_stream)."""
    return True


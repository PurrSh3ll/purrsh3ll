"""
health_check.py — startup dependency probe for PurrSh3ll.

The app leans on a handful of external tools and optional Python libraries.
None are strictly fatal (each path has a fallback or degrades gracefully),
but when one is missing the symptom shows up much later and looks like a
bug — e.g. screenshots without metadata (no exiftool), commands not typed
into an external terminal (no xdotool), RAG silently disabled (no chromadb).

This module probes them once at startup and logs a single summary line:
  - everything present  -> logger.info  (app.log only)
  - something missing    -> logger.warning (also console) listing the gaps

Per-item details go to logger.debug (visible under --debug). The structured
result is also returned so a future diagnostics panel can render it.
"""

import importlib.util
import logging
import os
import shutil

logger = logging.getLogger(__name__)

# External CLI tools: (name, what breaks without it)
_TOOLS = [
    ("xdotool",  "typing commands into external terminals"),
    ("exiftool", "media metadata extraction (image/pdf/video/audio)"),
    ("nmap",     "psnmap scanning module"),
    ("sudo",     "privileged operations"),
]

# Optional external tools: needed only by opt-in features the user can skip at
# install time and add later. Reported for visibility, but their absence does
# NOT mark the health-check as degraded (they are not counted in "missing").
_OPTIONAL_TOOLS = [
    ("ollama",   "default local LLM backend for AI features (ps*, voice, chat)"),
    ("aichat",   "chat panel CLI backend"),
    ("docker",   "WebMap (psnmap) and Open WebUI containers"),
]

# At least one of these is needed to launch an external terminal.
_TERMINALS = [
    "qterminal", "gnome-terminal", "xfce4-terminal",
    "konsole", "xterm", "tilix", "lxterminal",
]

# Optional Python libraries: (import name, what breaks without it)
_LIBS = [
    ("keyring",  "secure API-key storage (falls back to plaintext file)"),
    ("chromadb", "RAG vector store (RAG features disabled without it)"),
    ("fitz",     "fast PDF text extraction (falls back to pypdf)"),
    ("pygame",   "audio playback"),
    ("mutagen",  "audio metadata"),
]

# Optional Python libraries for opt-in features (installed by install.sh only
# when the feature is selected). Reported for visibility, but absence does NOT
# mark the health-check as degraded — same policy as _OPTIONAL_TOOLS.
_OPTIONAL_LIBS = [
    ("openwakeword",   "voice wake-word detection (Voice support)"),
    ("faster_whisper", "voice speech-to-text (Voice support)"),
    ("sounddevice",    "voice microphone capture (Voice support)"),
]


def _lib_available(name: str) -> bool:
    """True if the module can be located without importing it (cheap, no side effects)."""
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        # A broken/partial install can raise here; treat as unavailable.
        return False


def run_health_check(base_path: str) -> dict:
    """Probe tools, libraries and runtime paths. Returns a structured result:
        {"tools": {name: bool}, "terminal": bool, "libs": {name: bool},
         "paths": {label: bool}, "missing": [human-readable strings]}
    Pure inspection — nothing is created or modified.
    """
    tools = {name: shutil.which(name) is not None for name, _ in _TOOLS}
    optional_tools = {name: shutil.which(name) is not None for name, _ in _OPTIONAL_TOOLS}
    terminal = any(shutil.which(t) is not None for t in _TERMINALS)
    libs = {name: _lib_available(name) for name, _ in _LIBS}
    optional_libs = {name: _lib_available(name) for name, _ in _OPTIONAL_LIBS}

    appdata = os.path.join(base_path, "appdata")
    logs_dir = os.path.join(appdata, "logs")
    config = os.path.join(appdata, "app_config.json")
    paths = {
        "appdata writable": os.path.isdir(appdata) and os.access(appdata, os.W_OK),
        "logs writable": os.path.isdir(logs_dir) and os.access(logs_dir, os.W_OK),
        "config readable": os.path.isfile(config) and os.access(config, os.R_OK),
    }

    missing = []
    for name, why in _TOOLS:
        if not tools[name]:
            missing.append(f"{name} ({why})")
    if not terminal:
        missing.append("terminal emulator (launching external terminals)")
    for name, why in _LIBS:
        if not libs[name]:
            missing.append(f"{name} ({why})")
    for label, ok in paths.items():
        if not ok:
            missing.append(f"path: {label}")

    return {"tools": tools, "optional_tools": optional_tools, "terminal": terminal,
            "libs": libs, "optional_libs": optional_libs, "paths": paths,
            "missing": missing}


def log_health_summary(base_path: str) -> dict:
    """Run the probe and log it. One summary line (warning if anything is
    missing, info otherwise) plus per-item debug detail. Returns the result."""
    result = run_health_check(base_path)

    for name, why in _TOOLS:
        logger.debug("tool %-9s %s", name, "OK" if result["tools"][name] else f"MISSING — {why}")
    for name, why in _OPTIONAL_TOOLS:
        logger.debug("opt-tool %-9s %s", name,
                     "OK" if result["optional_tools"][name] else f"absent (optional) — {why}")
    logger.debug("terminal emulator %s", "OK" if result["terminal"] else "MISSING")
    for name, why in _LIBS:
        logger.debug("lib  %-9s %s", name, "OK" if result["libs"][name] else f"MISSING — {why}")
    for name, why in _OPTIONAL_LIBS:
        logger.debug("opt-lib %-14s %s", name,
                     "OK" if result["optional_libs"][name] else f"absent (optional) — {why}")
    for label, ok in result["paths"].items():
        logger.debug("path %-18s %s", label, "OK" if ok else "MISSING/UNWRITABLE")

    total = len(_TOOLS) + 1 + len(_LIBS) + len(result["paths"])
    ok_count = total - len(result["missing"])

    if result["missing"]:
        logger.warning(
            "health-check: %d/%d OK — degraded: %s",
            ok_count, total, "; ".join(result["missing"]),
        )
    else:
        logger.info("health-check: %d/%d OK — all dependencies present", ok_count, total)

    return result

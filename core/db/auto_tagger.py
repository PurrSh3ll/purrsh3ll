"""
auto_tagger.py — maps the first word of a shell command to tool category tags
loaded from appdata/tool_categories.json.

Usage:
    tagger = AutoTagger("/path/to/appdata/tool_categories.json")
    tags = tagger.get_tags("nmap -sV 10.10.10.1")  # → ["recon", "scan"]
    tags = tagger.get_tags("ls -la")                # → []
"""
from __future__ import annotations

import json


class AutoTagger:
    """Lazy-loading lookup: first word of a command → list of category tags."""

    def __init__(self, json_path: str) -> None:
        self._json_path = json_path
        self._tools: dict[str, list[str]] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        try:
            with open(self._json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._tools = data.get("tools", {})
        except Exception:
            self._tools = {}
        self._loaded = True

    def get_tags(self, cmd: str) -> list[str]:
        """Return category tags for the first word in cmd, or [] if unknown."""
        if not cmd or not cmd.strip():
            return []
        self._ensure_loaded()
        tool = cmd.strip().split()[0]
        return list(self._tools.get(tool, []))

    def reload(self) -> None:
        """Force reload on next call (e.g. after tool_categories.json is edited)."""
        self._loaded = False

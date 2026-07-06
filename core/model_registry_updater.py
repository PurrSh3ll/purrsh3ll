"""Refresh appdata/model_ctx_registry.json from the liteLLM model database.

Mechanism A: pull liteLLM's public ``model_prices_and_context_window.json``
(no API key required) and regenerate the per-provider ``models`` maps and
``no_tools`` lists, while preserving the curated provider-level fields
(``default`` ctx tier, ``tools_default``, ``tools_user_override``) and the
top-level notes.

Only the providers the app actually exposes are refreshed. The previous file is
backed up to ``model_ctx_registry.json.bak`` before writing.
"""

import copy
import json
import logging
import os
import time
import urllib.request

from PyQt6.QtCore import QThread, pyqtSignal

logger = logging.getLogger(__name__)

LITELLM_URL = (
    "https://raw.githubusercontent.com/BerriAI/litellm/main/"
    "model_prices_and_context_window.json"
)

# Providers kept as default-only: their per-model registry ctx is NOT populated,
# so resolution always falls to the curated `default`. Ollama serves `num_ctx`
# (default 4096, common on CPU-only / VM setups) regardless of a model's
# architecture-max context, so the liteLLM per-model maxes would overstate the
# real window. Users needing more set a per-profile override.
DEFAULT_ONLY_PROVIDERS = {"ollama"}

# Registry section name -> liteLLM `litellm_provider` value. Identity for all of
# these today, but kept explicit so a divergence is a one-line change.
PROVIDER_MAP = {
    "openai":      "openai",
    "anthropic":   "anthropic",
    "groq":        "groq",
    "openrouter":  "openrouter",
    "gemini":      "gemini",
    "mistral":     "mistral",
    "together_ai": "together_ai",
    "ollama":      "ollama",
    "huggingface": "huggingface",
}

_HTTP_TIMEOUT = 25


def fetch_litellm(timeout: int = _HTTP_TIMEOUT) -> dict:
    """Download and parse the liteLLM model database. Raises on failure."""
    req = urllib.request.Request(
        LITELLM_URL, headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _strip_provider_prefix(model_key: str, litellm_provider: str) -> str:
    """``groq/llama-3.1`` -> ``llama-3.1``; ``openrouter/anthropic/x`` -> ``anthropic/x``."""
    prefix = litellm_provider + "/"
    if model_key.startswith(prefix):
        return model_key[len(prefix):]
    return model_key


def build_registry(litellm_data: dict, existing: dict) -> tuple[dict, dict]:
    """Return (new_registry, stats) refreshed from liteLLM, preserving curated flags."""
    new_reg = copy.deepcopy(existing)
    stats = {"providers": {}, "total_models": 0}

    for section, ll_provider in PROVIDER_MAP.items():
        if section in DEFAULT_ONLY_PROVIDERS:
            # Force default-only: clear any per-model ctx so resolution uses the
            # curated `default` (e.g. Ollama's real 4096 num_ctx).
            sec = new_reg.get(section)
            if isinstance(sec, dict):
                sec["models"] = {}
                sec["no_tools"] = []
                sec["ctx_note"] = ("default-only: Ollama serves num_ctx (default 4096) "
                                   "regardless of model; set a per-profile override for more")
            continue

        models: dict[str, int] = {}
        no_tools: list[str] = []

        for raw_key, entry in litellm_data.items():
            if not isinstance(entry, dict):
                continue
            if entry.get("litellm_provider") != ll_provider:
                continue
            if entry.get("mode") != "chat":
                continue
            ctx = entry.get("max_input_tokens")
            if not isinstance(ctx, int):
                continue
            name = _strip_provider_prefix(raw_key, ll_provider)
            models[name] = ctx
            if entry.get("supports_function_calling") is False:
                no_tools.append(name)

        if not models:
            # Provider not present in liteLLM (e.g. huggingface) — leave as-is.
            continue

        section_data = new_reg.get(section)
        if not isinstance(section_data, dict):
            section_data = {"default": None, "tools_default": True, "tools_user_override": None}
            new_reg[section] = section_data

        old_models = section_data.get("models", {}) or {}
        added = [m for m in models if m not in old_models]
        removed = [m for m in old_models if m not in models]

        section_data["models"] = dict(sorted(models.items()))
        section_data["no_tools"] = sorted(set(no_tools))

        stats["providers"][section] = {
            "count": len(models),
            "added": len(added),
            "removed": len(removed),
            "no_tools": len(no_tools),
        }
        stats["total_models"] += len(models)

    new_reg["_source"] = "liteLLM model_prices_and_context_window.json"
    new_reg["_last_refreshed"] = time.strftime("%Y-%m-%d %H:%M:%S")
    return new_reg, stats


def update_model_database(base_path: str, timeout: int = _HTTP_TIMEOUT) -> dict:
    """Fetch, transform and write the registry. Returns a stats dict.

    Meant to be called from a worker thread. Backs up the old file first.
    """
    reg_path = os.path.join(base_path, "appdata", "model_ctx_registry.json")

    existing = {}
    if os.path.isfile(reg_path):
        try:
            with open(reg_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            logger.warning("existing model_ctx_registry.json unreadable; regenerating", exc_info=True)
            existing = {}

    litellm_data = fetch_litellm(timeout)
    new_reg, stats = build_registry(litellm_data, existing)

    if stats["total_models"] == 0:
        raise RuntimeError("liteLLM returned no usable models for known providers")

    backup_path = reg_path + ".bak"
    if os.path.isfile(reg_path):
        try:
            with open(reg_path, "r", encoding="utf-8") as src, \
                 open(backup_path, "w", encoding="utf-8") as dst:
                dst.write(src.read())
        except Exception:
            logger.debug("registry backup failed", exc_info=True)

    tmp_path = reg_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(new_reg, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, reg_path)

    stats["ok"] = True
    stats["backup"] = backup_path if os.path.isfile(backup_path) else None
    return stats


class ModelRegistryUpdateWorker(QThread):
    """Runs :func:`update_model_database` off the GUI thread."""

    result = pyqtSignal(dict)

    def __init__(self, base_path: str, parent=None):
        super().__init__(parent)
        self.base_path = base_path

    def run(self):
        try:
            self.result.emit(update_model_database(self.base_path))
        except Exception as e:
            logger.debug("model registry update failed", exc_info=True)
            self.result.emit({"ok": False, "error": str(e)})

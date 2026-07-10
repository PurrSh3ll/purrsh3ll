"""Refresh appdata/model_ctx_registry.json from the liteLLM model database.

Mechanism A: pull liteLLM's public ``model_prices_and_context_window.json``
(no API key required) and regenerate the per-provider ``models`` maps,
``no_tools`` lists and the ``vision``/``audio`` capability lists, while
preserving the curated provider-level fields (``default`` ctx tier,
``tools_default``, ``tools_user_override``) and the top-level notes.

Capability lists are opt-in (a name appears only if liteLLM reports the
capability): ``vision`` = ``supports_vision``, ``audio`` = ``supports_audio_input``.
Absence means "not multimodal / unknown" — the minority of models that carry
these flags in liteLLM, so gaps are expected and can be curated by hand.

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
MODELSDEV_URL  = "https://models.dev/api.json"
OPENROUTER_URL = "https://openrouter.ai/api/v1/models"

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

# Registry section name -> models.dev provider id. Mostly identity; gemini is
# served under `google` and Together under `togetherai` on models.dev.
MODELSDEV_MAP = {
    "openai":      "openai",
    "anthropic":   "anthropic",
    "groq":        "groq",
    "openrouter":  "openrouter",
    "gemini":      "google",
    "mistral":     "mistral",
    "together_ai": "togetherai",
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


def fetch_modelsdev(timeout: int = _HTTP_TIMEOUT) -> dict:
    """Download the models.dev catalog (provider -> {models: {...}}). Raises on failure."""
    req = urllib.request.Request(
        MODELSDEV_URL, headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def fetch_openrouter(timeout: int = _HTTP_TIMEOUT) -> list:
    """Download the live OpenRouter model list. Returns the ``data`` array. Raises on failure."""
    req = urllib.request.Request(
        OPENROUTER_URL, headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    return data.get("data", []) if isinstance(data, dict) else (data or [])


def _strip_provider_prefix(model_key: str, litellm_provider: str) -> str:
    """``groq/llama-3.1`` -> ``llama-3.1``; ``openrouter/anthropic/x`` -> ``anthropic/x``."""
    prefix = litellm_provider + "/"
    if model_key.startswith(prefix):
        return model_key[len(prefix):]
    return model_key


def build_registry(litellm_data: dict, existing: dict,
                   modelsdev_data: dict | None = None,
                   openrouter_data: list | None = None) -> tuple[dict, dict]:
    """Return (new_registry, stats) merged from liteLLM + models.dev + OpenRouter,
    preserving curated provider-level flags.

    Merge policy per model:
      * ctx / tool-calling — first definitive source wins, in the order
        liteLLM > models.dev > OpenRouter (curated liteLLM values are not
        overwritten; other sources only fill gaps and add new models).
      * vision / audio — union (opt-in): any source reporting the capability
        adds the model, minimising false negatives on multimodality.
    """
    new_reg = copy.deepcopy(existing)
    stats = {
        "providers": {}, "total_models": 0,
        "sources": {
            "litellm":    bool(litellm_data),
            "modelsdev":  bool(modelsdev_data),
            "openrouter": bool(openrouter_data),
        },
    }

    for section, ll_provider in PROVIDER_MAP.items():
        if section in DEFAULT_ONLY_PROVIDERS:
            # Force default-only: clear any per-model ctx so resolution uses the
            # curated `default` (e.g. Ollama's real 4096 num_ctx).
            sec = new_reg.get(section)
            if isinstance(sec, dict):
                sec["models"] = {}
                sec["no_tools"] = []
                sec["vision"] = []
                sec["audio"] = []
                sec["ctx_note"] = ("default-only: Ollama serves num_ctx (default 4096) "
                                   "regardless of model; set a per-profile override for more")
            continue

        ctx_map: dict[str, int] = {}     # name -> ctx (first source wins)
        tools_map: dict[str, bool] = {}  # name -> tool-calling (first definitive wins)
        vision: set[str] = set()
        audio: set[str] = set()

        def _ctx(name: str, val) -> None:
            if isinstance(val, int) and val > 0 and name not in ctx_map:
                ctx_map[name] = val

        def _tools(name: str, val) -> None:
            if val is not None and name not in tools_map:
                tools_map[name] = bool(val)

        # ── Source 1: liteLLM ──────────────────────────────────────────────
        for raw_key, entry in (litellm_data or {}).items():
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
            _ctx(name, ctx)
            _tools(name, entry.get("supports_function_calling"))
            if entry.get("supports_vision") is True:
                vision.add(name)
            if entry.get("supports_audio_input") is True:
                audio.add(name)

        # ── Source 2: models.dev ───────────────────────────────────────────
        md_provider = MODELSDEV_MAP.get(section)
        md_section = (modelsdev_data or {}).get(md_provider) if md_provider else None
        if isinstance(md_section, dict):
            for mid, m in (md_section.get("models") or {}).items():
                if not isinstance(m, dict):
                    continue
                mods = m.get("modalities") or {}
                out = mods.get("output") or []
                if out and "text" not in out:
                    continue  # skip tts / image-gen / embedding-only models
                _ctx(mid, (m.get("limit") or {}).get("context"))
                _tools(mid, m.get("tool_call"))
                inp = mods.get("input") or []
                if "image" in inp:
                    vision.add(mid)
                if "audio" in inp:
                    audio.add(mid)

        # ── Source 3: OpenRouter (its own catalog → the openrouter section) ─
        if section == "openrouter":
            for m in (openrouter_data or []):
                if not isinstance(m, dict):
                    continue
                name = m.get("id")
                if not name:
                    continue
                arch = m.get("architecture") or {}
                out = arch.get("output_modalities") or []
                if out and "text" not in out:
                    continue
                _ctx(name, m.get("context_length"))
                sp = m.get("supported_parameters")
                if isinstance(sp, list) and sp:
                    _tools(name, "tools" in sp)
                inp = arch.get("input_modalities") or []
                if "image" in inp:
                    vision.add(name)
                if "audio" in inp:
                    audio.add(name)

        if not (ctx_map or tools_map or vision or audio):
            # Provider absent from every source — leave curated section as-is.
            continue

        section_data = new_reg.get(section)
        if not isinstance(section_data, dict):
            section_data = {"default": None, "tools_default": True, "tools_user_override": None}
            new_reg[section] = section_data

        old_models = section_data.get("models", {}) or {}
        added = [m for m in ctx_map if m not in old_models]
        removed = [m for m in old_models if m not in ctx_map]
        no_tools = sorted(n for n, v in tools_map.items() if v is False)

        section_data["models"]   = dict(sorted(ctx_map.items()))
        section_data["no_tools"] = no_tools
        section_data["vision"]   = sorted(vision)
        section_data["audio"]    = sorted(audio)

        stats["providers"][section] = {
            "count": len(ctx_map),
            "added": len(added),
            "removed": len(removed),
            "no_tools": len(no_tools),
            "vision": len(vision),
            "audio": len(audio),
        }
        stats["total_models"] += len(ctx_map)

    new_reg["_source"] = "liteLLM + models.dev + OpenRouter"
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

    # Secondary sources are best-effort: a failure here must not abort the update.
    try:
        modelsdev_data = fetch_modelsdev(timeout)
    except Exception:
        logger.warning("models.dev fetch failed; continuing without it", exc_info=True)
        modelsdev_data = None
    try:
        openrouter_data = fetch_openrouter(timeout)
    except Exception:
        logger.warning("OpenRouter fetch failed; continuing without it", exc_info=True)
        openrouter_data = None

    new_reg, stats = build_registry(litellm_data, existing, modelsdev_data, openrouter_data)

    if stats["total_models"] == 0:
        raise RuntimeError("no usable models returned for known providers")

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

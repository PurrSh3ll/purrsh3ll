#!/usr/bin/env python3
# PurrSh3ll — conversation memory (semantic recall of older / cross-session turns)
# Copyright (C) 2024-2025  PurrSh3ll Contributors
#
# Fills purragent's reserved "memory lookup" context slot. Every completed
# exchange (a user turn + the assistant's reply) is embedded and appended to a
# small persistent per-workspace store; before a new turn, the current question
# is embedded and the most semantically similar PAST exchanges — including from
# earlier turns condensed out of the live window, and from OTHER sessions on the
# same workspace — are recalled and injected. It reuses the exact embedder the
# tool retriever and knowledge-base RAG use (appdata/rag settings), keeps the
# vectors in a numpy array next to a JSON sidecar, and degrades to a clean no-op
# when embeddings are unavailable.

import json
import os
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import tool_retriever          # reuse the embedding model name + cache dir helpers

MAX_ITEMS = 2000               # cap the store; oldest exchanges drop out (rolling)


class ConversationMemory:
    """Persistent per-workspace store of embedded exchanges with semantic recall.

    Lazy: the embedding model loads on first add/recall (shared with tool
    discovery, so usually already in memory). All methods no-op cleanly if the
    embedder can't be loaded."""

    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.model_name = tool_retriever._embedding_model_name(base_dir)
        self.cache_dir = tool_retriever._cache_dir(base_dir)
        self._model = None
        self._np = None
        self._matrix = None                # np.ndarray [n, dim] L2-normalised, or None
        self._items: list = []             # [{user, text, session, ts}]
        self._dir = os.path.join(base_dir, "appdata", "conv_memory")
        self._vec_path = os.path.join(self._dir, "vectors.npy")
        self._meta_path = os.path.join(self._dir, "meta.json")
        self._loaded = False
        self._lock = threading.Lock()      # add() runs in a background thread; recall in fg
        self.error = None

    # -- model ------------------------------------------------------------- #
    def _ensure_np(self) -> bool:
        """numpy only (cheap) — enough to load/search the store without the embedder."""
        if self._np is not None:
            return True
        try:
            import numpy as np
        except Exception as e:                         # pragma: no cover
            self.error = f"numpy unavailable: {e}"
            return False
        self._np = np
        return True

    def _ensure_model(self) -> bool:
        """The embedding model (heavy) — loaded only when we actually embed."""
        if not self._ensure_np():
            return False
        if self._model is not None:
            return True
        try:
            from core.rag import embedder
        except Exception as e:                         # pragma: no cover
            self.error = f"embeddings unavailable: {e}"
            return False
        try:
            self._model = embedder.load_model(self.model_name, self.cache_dir)
        except Exception as e:
            self.error = f"could not load embedding model: {e}"
            self._model = None
            return False
        return True

    def _embed(self, texts: list):
        from core.rag import embedder
        vecs = embedder.embed_batch(self._model, texts)
        m = self._np.asarray(vecs, dtype="float32")
        norms = self._np.linalg.norm(m, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return m / norms

    # -- persistence ------------------------------------------------------- #
    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            with open(self._meta_path, encoding="utf-8") as f:
                self._items = json.load(f)
            if self._items:
                self._matrix = self._np.load(self._vec_path)
            # Guard against a torn write: matrix rows must match item count.
            if self._matrix is not None and len(self._matrix) != len(self._items):
                self._items, self._matrix = [], None
        except Exception:                              # noqa: BLE001 — start empty
            self._items, self._matrix = [], None

    def _save(self) -> None:
        try:
            os.makedirs(self._dir, exist_ok=True)
            if self._matrix is not None:
                self._np.save(self._vec_path, self._matrix)
            with open(self._meta_path, "w", encoding="utf-8") as f:
                json.dump(self._items, f)
        except Exception:                              # noqa: BLE001 — non-fatal
            pass

    # -- index / recall ---------------------------------------------------- #
    def add(self, user_text: str, assistant_text: str, session: str) -> None:
        """Embed and store one completed exchange (persisted immediately). Safe to call
        from a background thread — the caller does, so it never blocks the REPL."""
        u = (user_text or "").strip()
        a = (assistant_text or "").strip()
        if not u:
            return
        with self._lock:
            if not self._ensure_model():
                return
            self._load()
            text = f"User: {u}\nAssistant: {a}" if a else f"User: {u}"
            try:
                vec = self._embed([text])              # [1, dim]
            except Exception:                          # noqa: BLE001
                return
            self._matrix = vec if self._matrix is None \
                else self._np.concatenate([self._matrix, vec], axis=0)
            self._items.append({"user": u, "text": text, "session": session,
                                "ts": int(time.time())})
            if len(self._items) > MAX_ITEMS:           # rolling cap: drop oldest
                drop = len(self._items) - MAX_ITEMS
                self._items = self._items[drop:]
                self._matrix = self._matrix[drop:]
            self._save()

    def recall(self, query: str, recent_users, top_k: int = 8,
               min_score: float = 0.35) -> list:
        """Top past exchanges most similar to `query`, excluding ones whose user turn is
        in `recent_users` (already verbatim in the live window). Returns [(text, score)].
        Loads the store with numpy only and skips the heavy embedder entirely when the
        store is empty, so the very first turns aren't blocked by a model load."""
        query = (query or "").strip()
        if not query or not self._ensure_np():
            return []
        with self._lock:
            self._load()
            if self._matrix is None or not self._items:
                return []                              # nothing stored → no model load
            if not self._ensure_model():
                return []
            try:
                q = self._embed([query])[0]
            except Exception:                          # noqa: BLE001
                return []
            sims = self._matrix @ q                    # cosine (all L2-normalised)
            recent = recent_users or set()
            scored = []
            for i, it in enumerate(self._items):
                if it.get("user") in recent:           # already in the recent window
                    continue
                s = float(sims[i])
                if s >= min_score:
                    scored.append((s, it.get("text", "")))
        scored.sort(reverse=True)
        return [(t, s) for s, t in scored[:top_k] if t]

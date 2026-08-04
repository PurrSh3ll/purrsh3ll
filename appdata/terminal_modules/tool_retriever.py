#!/usr/bin/env python3
# PurrSh3ll — MCP tool retriever (semantic tool discovery, no rerank)
# Copyright (C) 2024-2025  PurrSh3ll Contributors
#
# Client-side RAG over MCP tools. Instead of sending every tool's full schema to
# the model, purragent shows the model a short catalog plus one meta-function
# ("describe the tool you need"). The model's natural-language `need` is embedded
# here and compared against each tool's long description and example queries; the
# best-matching tools are then surfaced (with full schemas) for the model to call.
#
# This module only does the retrieval half (embed + cosine similarity, top-N).
# There is intentionally NO cross-encoder rerank step yet — that is a later,
# optional layer. For a handful of tools an in-memory vector table is simpler and
# faster than round-tripping ChromaDB, so we keep the vectors in a numpy array.
#
# The embedding model + cache directory mirror the app's RAG settings
# (appdata/app_config.json -> rag.embedding_model, appdata/rag/models), so the
# model is shared with the knowledge-base RAG and never downloaded twice.

import json
import os
import sys

# Reuse the app's embedding loader (built-in / hf: / local: models) so tool
# retrieval uses exactly the same embedder as the knowledge-base RAG.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_HERE))   # .../App_beta
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

DEFAULT_EMBEDDING_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
DEFAULT_RERANK_MODEL = "Xenova/ms-marco-MiniLM-L-12-v2"


def _app_config(base_dir: str) -> dict:
    try:
        with open(os.path.join(base_dir, "appdata", "app_config.json"),
                  encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _embedding_model_name(base_dir: str) -> str:
    return (_app_config(base_dir).get("rag", {})
            .get("embedding_model", DEFAULT_EMBEDDING_MODEL))


def _rerank_enabled(base_dir: str) -> bool:
    # Mirror the app's RAG setting: rerank tool matches only when the user has
    # turned reranking on in AI Settings.
    return bool(_app_config(base_dir).get("rag", {}).get("rerank", False))


def _rerank_model_name(base_dir: str) -> str:
    return (_app_config(base_dir).get("rag", {})
            .get("rerank_model", DEFAULT_RERANK_MODEL))


def _cache_dir(base_dir: str) -> str:
    return os.path.join(base_dir, "appdata", "rag", "models")


class ToolRetriever:
    """Embeds a set of MCP tools and returns the best matches for a free-text need.

    Build once from the aggregated tool list, then call retrieve() per meta-tool
    request. The embedding model is loaded lazily on first build and kept in
    memory for the life of the session (query embedding is then cheap).
    """

    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.model_name = _embedding_model_name(base_dir)
        self.cache_dir = _cache_dir(base_dir)
        self._model = None
        self._np = None
        # Parallel arrays: one row per indexed text, mapped back to its tool.
        self._matrix = None        # np.ndarray [n_vectors, dim], L2-normalised
        self._owners: list[str] = []   # namespaced tool name per row
        self._passages: dict[str, str] = {}   # tool name -> rerank passage (long)
        self._signature = None     # fingerprint of the indexed tool set
        self.error = None          # set to a string if the model failed to load
        # Optional cross-encoder rerank, gated on the app's rag.rerank setting.
        self.rerank_enabled = _rerank_enabled(base_dir)
        self.rerank_model_name = _rerank_model_name(base_dir)
        self._reranker = None      # lazily loaded; None while disabled/unavailable

    # -- model ------------------------------------------------------------- #
    def _ensure_model(self) -> bool:
        if self._model is not None:
            return True
        try:
            import numpy as np
            from core.rag import embedder
        except Exception as e:                       # pragma: no cover
            self.error = f"embeddings unavailable: {e}"
            return False
        try:
            self._np = np
            self._model = embedder.load_model(self.model_name, self.cache_dir)
        except Exception as e:
            self.error = f"could not load embedding model: {e}"
            self._model = None
            return False
        return True

    def _embed(self, texts: list[str]):
        """Return an L2-normalised numpy matrix for `texts` (rows = vectors)."""
        from core.rag import embedder
        vecs = embedder.embed_batch(self._model, texts)
        m = self._np.asarray(vecs, dtype="float32")
        norms = self._np.linalg.norm(m, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return m / norms

    # -- indexing ---------------------------------------------------------- #
    @staticmethod
    def _signature_of(tools: list) -> tuple:
        # Rebuild only when the tool set or its descriptions actually change.
        return tuple(sorted(
            (t.get("name", ""), t.get("long", ""),
             tuple(t.get("examples", []) or []))
            for t in tools
        ))

    def build(self, tools: list) -> bool:
        """Index tools: a list of dicts {name, long, examples[, short]}.

        Each tool contributes several vectors — its long description plus one per
        example query — and retrieval max-pools over them, so a short user need
        can match either the prose or a close example phrasing. Returns success;
        on failure sets self.error and leaves the retriever empty.
        """
        sig = self._signature_of(tools)
        if sig == self._signature and self._matrix is not None:
            return True                              # already indexed, unchanged
        if not self._ensure_model():
            return False

        texts: list[str] = []
        owners: list[str] = []
        passages: dict[str, str] = {}
        for t in tools:
            name = t.get("name", "")
            long = (t.get("long") or t.get("short") or "").strip()
            if long:
                texts.append(long)
                owners.append(name)
            examples = [e.strip() for e in (t.get("examples") or []) if e and e.strip()]
            for ex in examples:
                texts.append(ex)
                owners.append(name)
            # The rerank passage is the short description plus the example queries,
            # not the long prose: the long text carries keyword dumps and "not for
            # X, use Y" cross-references that mislead a lexical-ish cross-encoder
            # (e.g. read_file matching "scan output"). Short + intent-shaped
            # examples give it a cleaner, query-like signal to score against.
            short = (t.get("short") or "").strip()
            passages[name] = ". ".join([p for p in ([short] + examples) if p]) or long
        if not texts:
            self.error = "no tool text to index"
            return False
        try:
            self._matrix = self._embed(texts)
        except Exception as e:
            self.error = f"failed to embed tools: {e}"
            return False
        self._owners = owners
        self._passages = passages
        self._signature = sig
        return True

    # -- rerank (optional) ------------------------------------------------- #
    def _ensure_reranker(self):
        """Lazily load the cross-encoder. Returns it, or None if disabled or the
        model can't be loaded (retrieval then keeps the embedding order)."""
        if not self.rerank_enabled:
            return None
        if self._reranker is not None:
            return self._reranker
        import warnings
        try:
            from fastembed.rerank.cross_encoder import TextCrossEncoder
            kwargs = {"cache_dir": self.cache_dir} if self.cache_dir else {}
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                # Built-in model ids load directly; hf:/local: prefixes are rare
                # for rerankers so we keep this to the common built-in path.
                self._reranker = TextCrossEncoder(
                    model_name=self.rerank_model_name, **kwargs)
        except Exception as e:
            self.error = f"could not load rerank model: {e}"
            self.rerank_enabled = False       # don't retry every query
            self._reranker = None
        return self._reranker

    # -- query ------------------------------------------------------------- #
    def retrieve(self, need: str, top_n: int = 3) -> list:
        """Return up to top_n (namespaced_name, score) best matches for `need`.

        First stage: embedding cosine similarity, max-pooled per tool. If the app
        has reranking enabled, a wider candidate pool from that stage is re-scored
        by the cross-encoder and the top_n taken from there; otherwise the
        embedding order is used directly. Returns [] if not built / empty query.
        """
        if self._matrix is None or not need or not need.strip():
            return []
        need = need.strip()
        try:
            q = self._embed([need])[0]                # [dim]
        except Exception as e:
            self.error = f"failed to embed query: {e}"
            return []
        sims = self._matrix @ q                        # cosine (all L2-normalised)
        best: dict[str, float] = {}
        for owner, score in zip(self._owners, sims):
            s = float(score)
            if owner not in best or s > best[owner]:
                best[owner] = s
        ranked = sorted(best.items(), key=lambda kv: kv[1], reverse=True)
        top_n = max(0, int(top_n))

        reranker = self._ensure_reranker()
        if reranker is None or len(ranked) <= 1:
            return ranked[:top_n]

        # Rerank a wider pool so the cross-encoder can reorder beyond the top_n
        # the embedding stage would have returned.
        pool = ranked[:min(len(ranked), max(top_n * 3, 8))]
        names = [n for n, _ in pool]
        passages = [self._passages.get(n, "") for n in names]
        try:
            scores = list(reranker.rerank(need, passages))
        except Exception as e:
            self.error = f"rerank failed: {e}"
            return ranked[:top_n]                      # fall back to embedding order
        reranked = sorted(zip(names, scores), key=lambda kv: kv[1], reverse=True)
        return [(n, float(s)) for n, s in reranked[:top_n]]


# --------------------------------------------------------------------------- #
# Standalone smoke test:  python3 tool_retriever.py [--base-dir .] [need...]
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import mcp_client

    argv = sys.argv[1:]
    base = "."
    if "--base-dir" in argv:
        i = argv.index("--base-dir")
        base = argv[i + 1]
        del argv[i:i + 2]
    base = os.path.abspath(base)
    need = " ".join(argv) if argv else None

    mgr = mcp_client.MCPManager(base)
    mgr.connect()
    tools = mgr.all_tools()
    print(f"indexing {len(tools)} tools from {list(mgr.servers)} …")

    r = ToolRetriever(base)
    if not r.build(tools):
        print(f"build failed: {r.error}")
        mgr.close()
        sys.exit(1)

    queries = [need] if need else [
        "scan a host for open ports",
        "read what is inside a config file",
        "save the results to a file",
        "download a web page and check its headers",
        "find a password somewhere in the source code",
        "change one value in a settings file",
    ]
    for qn in queries:
        hits = r.retrieve(qn, top_n=3)
        pretty = ", ".join(f"{name.split('__')[-1]} ({score:.2f})"
                            for name, score in hits)
        print(f"\n  need: {qn}\n   -> {pretty}")
    mgr.close()

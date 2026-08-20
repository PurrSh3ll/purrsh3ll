"""Tests for the MCP tool retriever (tool_retriever).

This is the semantic tool-discovery layer that lets purragent attach unlimited
MCP servers without prompt bloat: tools are embedded and the best matches for a
free-text need are surfaced. We test the config helpers, the index signature,
and build()/retrieve() with a deterministic bag-of-words embedder (no model
download) so ranking is predictable. Reranking stays off (app default), so
retrieve() returns pure embedding order.
"""

import json

import numpy as np
import pytest

import tool_retriever as tr


_VOCAB = ["scan", "port", "read", "file", "write", "save", "host"]


def _fake_embed(texts):
    rows = [[float(t.lower().count(w)) for w in _VOCAB] for t in texts]
    m = np.asarray(rows, dtype="float32")
    norms = np.linalg.norm(m, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return m / norms


_TOOLS = [
    {"name": "srv__scanner", "short": "port scanner",
     "long": "scan hosts for open ports and services",
     "examples": ["scan a host", "find open ports"]},
    {"name": "srv__reader", "short": "file reader",
     "long": "read the contents of a file",
     "examples": ["read a config file"]},
    {"name": "srv__writer", "short": "file writer",
     "long": "write content to a file",
     "examples": ["save results to a file"]},
]


def _retriever(base_dir):
    r = tr.ToolRetriever(str(base_dir))

    def _ensure():
        r._np = np
        r._model = object()
        return True

    r._ensure_model = _ensure
    r._embed = _fake_embed
    return r


# --------------------------------------------------------------------------- #
# config helpers
# --------------------------------------------------------------------------- #
def test_defaults_when_no_config(tmp_path):
    assert tr._embedding_model_name(str(tmp_path)) == tr.DEFAULT_EMBEDDING_MODEL
    assert tr._rerank_enabled(str(tmp_path)) is False
    assert tr._rerank_model_name(str(tmp_path)) == tr.DEFAULT_RERANK_MODEL


def test_config_overrides_are_read(tmp_path):
    (tmp_path / "appdata").mkdir()
    (tmp_path / "appdata" / "app_config.json").write_text(json.dumps({
        "rag": {"embedding_model": "hf:custom/model",
                "rerank": True,
                "rerank_model": "custom/reranker"}
    }))
    assert tr._embedding_model_name(str(tmp_path)) == "hf:custom/model"
    assert tr._rerank_enabled(str(tmp_path)) is True
    assert tr._rerank_model_name(str(tmp_path)) == "custom/reranker"


def test_bad_config_falls_back_to_defaults(tmp_path):
    (tmp_path / "appdata").mkdir()
    (tmp_path / "appdata" / "app_config.json").write_text("{ not valid json")
    assert tr._embedding_model_name(str(tmp_path)) == tr.DEFAULT_EMBEDDING_MODEL


def test_cache_dir_path(tmp_path):
    expected = str(tmp_path / "appdata" / "rag" / "models")
    assert tr._cache_dir(str(tmp_path)) == expected


# --------------------------------------------------------------------------- #
# _signature_of
# --------------------------------------------------------------------------- #
def test_signature_is_order_independent():
    sig_a = tr.ToolRetriever._signature_of(_TOOLS)
    sig_b = tr.ToolRetriever._signature_of(list(reversed(_TOOLS)))
    assert sig_a == sig_b


def test_signature_changes_with_description():
    changed = [dict(t) for t in _TOOLS]
    changed[0] = dict(changed[0], long="a totally different description")
    assert tr.ToolRetriever._signature_of(_TOOLS) != \
        tr.ToolRetriever._signature_of(changed)


# --------------------------------------------------------------------------- #
# build / retrieve
# --------------------------------------------------------------------------- #
def test_retrieve_before_build_returns_empty(tmp_path):
    r = _retriever(tmp_path)
    assert r.retrieve("scan ports") == []


def test_build_then_retrieve_matches_scanner(tmp_path):
    r = _retriever(tmp_path)
    assert r.build(_TOOLS) is True
    hits = r.retrieve("scan open ports on a host", top_n=3)
    assert hits[0][0] == "srv__scanner"


def test_retrieve_matches_reader_for_read_need(tmp_path):
    r = _retriever(tmp_path)
    r.build(_TOOLS)
    hits = r.retrieve("read a file", top_n=3)
    assert hits[0][0] == "srv__reader"


def test_retrieve_matches_writer_for_save_need(tmp_path):
    r = _retriever(tmp_path)
    r.build(_TOOLS)
    hits = r.retrieve("save results to a file", top_n=3)
    assert hits[0][0] == "srv__writer"


def test_retrieve_empty_query_returns_empty(tmp_path):
    r = _retriever(tmp_path)
    r.build(_TOOLS)
    assert r.retrieve("   ") == []


def test_retrieve_respects_top_n(tmp_path):
    r = _retriever(tmp_path)
    r.build(_TOOLS)
    assert len(r.retrieve("file", top_n=1)) == 1
    assert len(r.retrieve("file", top_n=2)) == 2


def test_retrieve_max_pools_one_score_per_tool(tmp_path):
    r = _retriever(tmp_path)
    r.build(_TOOLS)
    hits = r.retrieve("scan a host for open ports", top_n=10)
    owners = [name for name, _ in hits]
    # scanner indexes 3 vectors (long + 2 examples) but appears once.
    assert owners.count("srv__scanner") == 1
    assert len(owners) == len(set(owners))


def test_build_empty_tools_fails_gracefully(tmp_path):
    r = _retriever(tmp_path)
    assert r.build([]) is False
    assert r.error is not None
    assert r.retrieve("anything") == []


def test_build_is_cached_by_signature(tmp_path):
    r = _retriever(tmp_path)
    assert r.build(_TOOLS) is True
    # Second build with identical tools short-circuits (returns True, keeps index).
    assert r.build(_TOOLS) is True
    assert r._matrix is not None

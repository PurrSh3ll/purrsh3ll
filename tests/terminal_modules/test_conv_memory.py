"""Tests for purragent's conversation memory (conv_memory.ConversationMemory).

The store embeds each completed exchange and recalls semantically similar past
turns. To keep tests deterministic and offline we replace the heavy embedding
model with a tiny bag-of-words embedder over a fixed vocabulary — cosine
similarity then just reflects word overlap, so recall ordering is predictable.
We never load a real model. Focus: add/persist, recall (similarity, recent
exclusion, min_score, top_k), reset, graceful no-op paths, and persistence
across instances.
"""

import numpy as np
import pytest

import conv_memory


_VOCAB = ["alpha", "beta", "gamma", "delta"]


def _fake_embed(texts):
    """Deterministic L2-normalised vectors: counts of each vocab word per text."""
    rows = [[float(t.lower().count(w)) for w in _VOCAB] for t in texts]
    m = np.asarray(rows, dtype="float32")
    norms = np.linalg.norm(m, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return m / norms


def _mem(base_dir):
    """A ConversationMemory wired to the fake embedder (no model download)."""
    m = conv_memory.ConversationMemory(str(base_dir))
    # _ensure_model normally loads the heavy model; here just ensure numpy is set
    # (real code path minus the model) and report success.
    m._ensure_model = m._ensure_np
    m._embed = _fake_embed
    return m


@pytest.fixture
def mem(tmp_path):
    return _mem(tmp_path)


# --------------------------------------------------------------------------- #
# add / persistence
# --------------------------------------------------------------------------- #
def test_add_stores_item_and_persists_files(mem):
    mem.add("tell me about alpha", "alpha is the first", session="s1")
    assert len(mem._items) == 1
    assert mem._matrix.shape == (1, len(_VOCAB))
    # Persisted to disk immediately.
    import os
    assert os.path.exists(mem._meta_path)
    assert os.path.exists(mem._vec_path)


def test_add_ignores_empty_user_turn(mem):
    mem.add("   ", "some assistant reply", session="s1")
    assert mem._items == []
    assert mem._matrix is None


def test_add_matrix_grows_with_each_exchange(mem):
    mem.add("about alpha", "alpha", session="s1")
    mem.add("about beta", "beta", session="s1")
    mem.add("about gamma", "gamma", session="s1")
    assert len(mem._items) == 3
    assert mem._matrix.shape == (3, len(_VOCAB))


def test_add_noop_when_model_unavailable(tmp_path):
    m = conv_memory.ConversationMemory(str(tmp_path))
    m._ensure_model = lambda: False        # embedder can't load
    m.add("about alpha", "alpha", session="s1")
    assert m._items == [] and m._matrix is None


# --------------------------------------------------------------------------- #
# recall
# --------------------------------------------------------------------------- #
def test_recall_empty_query_returns_empty(mem):
    mem.add("about alpha", "alpha", session="s1")
    assert mem.recall("", recent_users=set()) == []


def test_recall_empty_store_returns_empty(mem):
    assert mem.recall("about alpha", recent_users=set()) == []


def test_recall_finds_semantically_similar_exchange(mem):
    mem.add("tell me about alpha", "alpha details", session="s1")
    mem.add("tell me about beta", "beta details", session="s1")

    hits = mem.recall("more on alpha please", recent_users=set())
    assert len(hits) == 1
    text, score = hits[0]
    assert "alpha" in text
    assert score >= 0.35


def test_recall_excludes_recent_user_turns(mem):
    mem.add("tell me about alpha", "alpha details", session="s1")
    # The matching exchange's user turn is already in the live window → excluded.
    hits = mem.recall("more alpha", recent_users={"tell me about alpha"})
    assert hits == []


def test_recall_respects_min_score(mem):
    mem.add("tell me about beta", "beta details", session="s1")
    # Query about alpha is orthogonal to the beta exchange (cosine 0) → filtered.
    assert mem.recall("alpha alpha", recent_users=set(), min_score=0.35) == []


def test_recall_respects_top_k_and_orders_by_score(mem):
    # Two alpha-ish exchanges with different strengths + one unrelated.
    mem.add("alpha alpha alpha", "strong alpha", session="s1")   # user counts: alpha=3
    mem.add("alpha and beta", "mixed", session="s1")             # alpha=1, beta=1
    mem.add("gamma only", "unrelated", session="s1")

    hits = mem.recall("alpha", recent_users=set(), top_k=1)
    assert len(hits) == 1
    # The strongest alpha match wins.
    assert "strong alpha" in hits[0][0]


# --------------------------------------------------------------------------- #
# reset
# --------------------------------------------------------------------------- #
def test_reset_clears_memory_and_files(mem):
    mem.add("about alpha", "alpha", session="s1")
    import os
    assert os.path.exists(mem._meta_path)

    mem.reset()
    assert mem._items == [] and mem._matrix is None
    assert not os.path.exists(mem._meta_path)
    assert not os.path.exists(mem._vec_path)
    # Recall after reset finds nothing.
    assert mem.recall("about alpha", recent_users=set()) == []


def test_reset_on_empty_store_is_safe(mem):
    mem.reset()   # must not raise
    assert mem._items == []


# --------------------------------------------------------------------------- #
# persistence across instances
# --------------------------------------------------------------------------- #
def test_store_persists_across_instances(tmp_path):
    m1 = _mem(tmp_path)
    m1.add("tell me about alpha", "alpha details", session="s1")

    # A fresh instance on the same base_dir loads the persisted store from disk.
    m2 = _mem(tmp_path)
    hits = m2.recall("alpha please", recent_users=set())
    assert len(hits) == 1
    assert "alpha" in hits[0][0]

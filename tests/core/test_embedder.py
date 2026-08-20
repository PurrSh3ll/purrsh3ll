"""Tests for the embedding-model helpers (core/rag/embedder).

Focus on the deterministic, dependency-free paths of is_model_cached (the
"should we show a Downloading… notice?" decision) plus the safe fallbacks of
_lookup_builtin_repo and _probe_dim. We deliberately avoid asserting anything
that requires fastembed/onnxruntime to be installed, so these run in the minimal
CI environment.
"""

from core.rag import embedder as emb


# --------------------------------------------------------------------------- #
# is_model_cached — resolvable, dependency-free paths
# --------------------------------------------------------------------------- #
def test_none_when_no_cache_dir():
    assert emb.is_model_cached("any/model", "") is None
    assert emb.is_model_cached("any/model", None) is None


def test_local_model_is_always_cached():
    assert emb.is_model_cached("local:/opt/models/mymodel", "some_cache") is True


def test_hf_model_absent_folder_is_false(tmp_path):
    assert emb.is_model_cached("hf:org/model", str(tmp_path)) is False


def test_hf_model_with_onnx_is_true(tmp_path):
    folder = tmp_path / "models--org--model"
    (folder / "onnx").mkdir(parents=True)
    (folder / "onnx" / "model.onnx").write_bytes(b"\x00")
    assert emb.is_model_cached("hf:org/model", str(tmp_path)) is True


def test_hf_model_folder_without_onnx_is_false(tmp_path):
    folder = tmp_path / "models--org--model"
    folder.mkdir()
    (folder / "config.json").write_text("{}")
    assert emb.is_model_cached("hf:org/model", str(tmp_path)) is False


def test_hf_model_strips_trailing_revision(tmp_path):
    # "hf:org/model:rev" resolves to repo "org/model".
    folder = tmp_path / "models--org--model"
    folder.mkdir()
    (folder / "m.onnx").write_bytes(b"\x00")
    assert emb.is_model_cached("hf:org/model:main", str(tmp_path)) is True


# --------------------------------------------------------------------------- #
# safe fallbacks
# --------------------------------------------------------------------------- #
def test_lookup_unknown_builtin_returns_none():
    assert emb._lookup_builtin_repo("definitely-not-a-real-model") is None


def test_probe_dim_falls_back_on_bad_path():
    assert emb._probe_dim("/nonexistent/dir", "missing.onnx") == 384

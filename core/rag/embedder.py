import gc
import os

DEFAULT_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"


def is_model_cached(model_name: str, cache_dir: str):
    """Return whether an embedding model is already present in cache_dir.

    True  — cached (loading will not download)
    False — absent (loading will download it from HuggingFace on first use)
    None  — unknown (mapping could not be resolved; caller should show no notice)

    Used to decide whether to surface a "Downloading model…" notice before a
    (potentially slow, hundreds-of-MB) first-time model load.
    """
    if not cache_dir:
        return None
    if model_name.startswith("local:"):
        return True  # local ONNX never downloads
    if model_name.startswith("hf:"):
        repo = model_name[3:].split(":", 1)[0]
    else:
        repo = _lookup_builtin_repo(model_name)
        if not repo:
            return None
    folder = os.path.join(cache_dir, "models--" + repo.replace("/", "--"))
    if not os.path.isdir(folder):
        return False
    for _root, _dirs, files in os.walk(folder):
        if any(f.endswith(".onnx") for f in files):
            return True
    return False


def _lookup_builtin_repo(model_name: str):
    """Resolve a built-in fastembed model name to its HuggingFace source repo."""
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from fastembed import TextEmbedding
            models = TextEmbedding.list_supported_models()
    except Exception:
        return None
    for m in models:
        name = m.get("model") if isinstance(m, dict) else getattr(m, "model", None)
        if name == model_name:
            src = m.get("sources") if isinstance(m, dict) else getattr(m, "sources", None)
            if isinstance(src, dict):
                return src.get("hf")
            return getattr(src, "hf", None)
    return None


def _probe_dim(model_dir: str, onnx_rel: str) -> int:
    """Read embedding output dimension from an ONNX file without fully loading the model."""
    try:
        import onnxruntime as ort
        path = os.path.join(model_dir, onnx_rel)
        sess = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
        dim = sess.get_outputs()[0].shape[-1]
        return int(dim) if isinstance(dim, int) else 384
    except Exception:
        return 384  # safe fallback


def _load_custom_hf(model_name: str, kwargs: dict):
    """Load a HuggingFace model not in fastembed's built-in list.
    model_name format: 'hf:org/repo:onnx/model.onnx'
    """
    from fastembed.text.custom_text_embedding import CustomTextEmbedding
    from fastembed.common.model_description import DenseModelDescription, ModelSource, PoolingType

    rest     = model_name[3:]                         # 'org/repo:onnx/model.onnx'
    parts    = rest.split(":", 1)
    hf_id    = parts[0]
    onnx_rel = parts[1] if len(parts) > 1 else "onnx/model.onnx"

    if not any(m.model == hf_id for m in CustomTextEmbedding.SUPPORTED_MODELS):
        desc = DenseModelDescription(
            model=hf_id,
            sources=ModelSource(hf=hf_id),
            model_file=onnx_rel,
            description=f"Custom HF model: {hf_id}",
            license="unknown",
            size_in_GB=0.5,
            dim=384,  # placeholder — fastembed uses actual ONNX output at runtime
        )
        CustomTextEmbedding.add_model(desc, PoolingType.MEAN, True)

    return CustomTextEmbedding(model_name=hf_id, **kwargs)


def _load_custom_local(model_name: str, kwargs: dict):
    """Load a local ONNX embedding model.
    model_name format: 'local:/path/to/model/dir:onnx/model.onnx'
    """
    from fastembed.text.custom_text_embedding import CustomTextEmbedding
    from fastembed.common.model_description import DenseModelDescription, ModelSource, PoolingType

    rest     = model_name[6:]                         # '/path/to/dir:onnx/model.onnx'
    parts    = rest.split(":", 1)
    model_dir = os.path.abspath(parts[0])
    onnx_rel  = parts[1] if len(parts) > 1 else "onnx/model.onnx"
    model_key = f"local:{model_dir}:{onnx_rel}"

    if not any(m.model == model_key for m in CustomTextEmbedding.SUPPORTED_MODELS):
        dim = _probe_dim(model_dir, onnx_rel)
        desc = DenseModelDescription(
            model=model_key,
            sources=ModelSource(hf=model_key),  # dummy — overridden by specific_model_path
            model_file=onnx_rel,
            description="Local ONNX embedding model",
            license="unknown",
            size_in_GB=0.5,
            dim=dim,
        )
        CustomTextEmbedding.add_model(desc, PoolingType.MEAN, True)

    return CustomTextEmbedding(model_name=model_key, specific_model_path=model_dir, **kwargs)


def load_model(model_name: str = DEFAULT_MODEL, cache_dir: str = ""):
    """Load and return an embedding model instance. Caller must call unload_model() when done."""
    import warnings
    kwargs = {}
    if cache_dir:
        kwargs["cache_dir"] = cache_dir

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if model_name.startswith("hf:"):
            return _load_custom_hf(model_name, kwargs)
        if model_name.startswith("local:"):
            return _load_custom_local(model_name, kwargs)
        from fastembed import TextEmbedding
        return TextEmbedding(model_name=model_name, **kwargs)


def embed_batch(model, texts: list[str]) -> list[list[float]]:
    """Embed texts using an already-loaded model instance. No load/unload overhead."""
    if not texts:
        return []
    return [v.tolist() for v in model.embed(texts)]


def unload_model(model) -> None:
    """Release model from memory."""
    del model
    gc.collect()


def embed(texts: list[str], model_name: str = DEFAULT_MODEL, cache_dir: str = "") -> list[list[float]]:
    """
    Embed a list of texts using fastembed.
    Model is loaded, used, then immediately released from memory.
    For bulk indexing prefer load_model() / embed_batch() / unload_model().
    """
    if not texts:
        return []
    model = load_model(model_name, cache_dir)
    try:
        return embed_batch(model, texts)
    finally:
        unload_model(model)

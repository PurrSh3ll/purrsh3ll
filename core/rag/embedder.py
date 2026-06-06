import gc
import os

DEFAULT_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"


def _is_custom(model_name: str) -> bool:
    return model_name.startswith("hf:") or model_name.startswith("local:")


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

    registered = {m["model"] for m in CustomTextEmbedding.list_supported_models()}
    if hf_id not in registered:
        desc = DenseModelDescription(
            model=hf_id,
            sources=ModelSource(hf=hf_id),
            model_file=onnx_rel,
            description=f"Custom HF model: {hf_id}",
            license="unknown",
            size_in_GB=0.5,
        )
        CustomTextEmbedding.add_model(desc, PoolingType.MEAN, True)

    return CustomTextEmbedding(model_name=hf_id, **kwargs)


def _load_custom_local(model_name: str, kwargs: dict):
    """Load a local ONNX embedding model.
    model_name format: 'local:/path/to/model.onnx'
    """
    from fastembed.text.custom_text_embedding import CustomTextEmbedding
    from fastembed.common.model_description import DenseModelDescription, ModelSource, PoolingType

    local_path = model_name[6:]
    model_dir  = os.path.dirname(os.path.abspath(local_path))
    onnx_file  = os.path.basename(local_path)
    model_key  = f"local:{local_path}"

    registered = {m["model"] for m in CustomTextEmbedding.list_supported_models()}
    if model_key not in registered:
        desc = DenseModelDescription(
            model=model_key,
            sources=ModelSource(),
            model_file=onnx_file,
            description="Local ONNX embedding model",
            license="unknown",
            size_in_GB=0.5,
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

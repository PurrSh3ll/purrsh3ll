import gc
import os

DEFAULT_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"


def load_model(model_name: str = DEFAULT_MODEL, cache_dir: str = ""):
    """Load and return a TextEmbedding model instance. Caller must call unload_model() when done."""
    try:
        from fastembed import TextEmbedding
    except ImportError:
        raise ImportError("fastembed is not installed. Run: pip install fastembed")

    kwargs = {"model_name": model_name}
    if cache_dir:
        kwargs["cache_dir"] = cache_dir

    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return TextEmbedding(**kwargs)


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

import gc
import os

DEFAULT_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"


def embed(texts: list[str], model_name: str = DEFAULT_MODEL, cache_dir: str = "") -> list[list[float]]:
    """
    Embed a list of texts using fastembed.
    Model is loaded, used, then immediately released from memory.
    Returns a list of float vectors.
    """
    if not texts:
        return []

    try:
        from fastembed import TextEmbedding
    except ImportError:
        raise ImportError(
            "fastembed is not installed. Run: pip install fastembed"
        )

    kwargs = {"model_name": model_name}
    if cache_dir:
        kwargs["cache_dir"] = cache_dir

    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        model = TextEmbedding(**kwargs)
    try:
        vectors = [v.tolist() for v in model.embed(texts)]
    finally:
        del model
        gc.collect()

    return vectors

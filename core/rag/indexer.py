import hashlib
import json
import os
import uuid

from core.rag import chunker
from core.rag import embedder as emb

_BATCH_SIZE = 32


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(65536), b""):
                h.update(block)
    except OSError:
        return ""
    return h.hexdigest()


def _load_meta(meta_path: str) -> dict:
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_meta(meta_path: str, meta: dict) -> None:
    os.makedirs(os.path.dirname(meta_path), exist_ok=True)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)


def _collect_files(kb_path: str) -> list[str]:
    files = []
    for root, _, names in os.walk(kb_path):
        for name in names:
            files.append(os.path.join(root, name))
    return sorted(files)


class Indexer:
    def __init__(self, kb_path: str, base_path: str, model_name: str = emb.DEFAULT_MODEL):
        self.kb_path    = os.path.normpath(kb_path)
        self.base_path  = base_path
        self.model_name = model_name

        self._rag_dir   = os.path.join(base_path, "appdata", "rag")
        self._db_path   = os.path.join(self._rag_dir, "chroma_db")
        self._meta_path = os.path.join(self._rag_dir, "index_meta.json")
        self._cache_dir = os.path.join(self._rag_dir, "models")

        os.makedirs(self._rag_dir, exist_ok=True)

        try:
            import chromadb
        except ImportError:
            raise ImportError("chromadb is not installed. Run: pip install chromadb")

        try:
            from chromadb.api.client import SharedSystemClient
            SharedSystemClient.clear_system_cache()
        except Exception:
            pass

        self._client     = chromadb.PersistentClient(path=self._db_path)
        self._collection = self._client.get_or_create_collection(
            name="rag_kb",
            metadata={"hnsw:space": "cosine"},
        )

    def index_all(self, progress_callback=None) -> None:
        """
        Full incremental index of kb_path.
        progress_callback(current, total, filename) called for each file processed.
        """
        meta     = _load_meta(self._meta_path)
        all_files = _collect_files(self.kb_path)
        total     = len(all_files)

        # Track which absolute paths still exist (for cleanup)
        existing_abs = set(all_files)

        for idx, abs_path in enumerate(all_files):
            filename = os.path.basename(abs_path)
            if progress_callback:
                progress_callback(idx + 1, total, filename)

            file_hash = _sha256(abs_path)
            if not file_hash:
                continue

            cached = meta.get(abs_path, {})
            if cached.get("sha256") == file_hash:
                continue  # unchanged — skip

            # Remove stale chunks for this file
            old_ids = cached.get("chunk_ids", [])
            if old_ids:
                try:
                    self._collection.delete(ids=old_ids)
                except Exception:
                    pass

            # Chunk
            chunks = chunker.chunk_file(abs_path, self.kb_path)
            if not chunks:
                meta[abs_path] = {"sha256": file_hash, "chunk_ids": []}
                continue

            # Embed in batches
            all_ids       = []
            all_docs      = []
            all_metas     = []
            all_embeddings = []

            texts = [c["text"] for c in chunks]
            metas = [c["metadata"] for c in chunks]

            for batch_start in range(0, len(texts), _BATCH_SIZE):
                batch_texts = texts[batch_start:batch_start + _BATCH_SIZE]
                batch_metas = metas[batch_start:batch_start + _BATCH_SIZE]

                vectors = emb.embed(batch_texts, self.model_name, self._cache_dir)

                for text, meta_item, vec in zip(batch_texts, batch_metas, vectors):
                    chunk_id = str(uuid.uuid4())
                    all_ids.append(chunk_id)
                    all_docs.append(text)
                    all_metas.append(meta_item)
                    all_embeddings.append(vec)

            # Store in ChromaDB
            self._collection.add(
                ids=all_ids,
                documents=all_docs,
                metadatas=all_metas,
                embeddings=all_embeddings,
            )

            meta[abs_path] = {"sha256": file_hash, "chunk_ids": all_ids}

        # Remove deleted files from DB and meta
        for abs_path in list(meta.keys()):
            if abs_path not in existing_abs:
                old_ids = meta[abs_path].get("chunk_ids", [])
                if old_ids:
                    try:
                        self._collection.delete(ids=old_ids)
                    except Exception:
                        pass
                del meta[abs_path]

        _save_meta(self._meta_path, meta)

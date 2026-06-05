import os

SUPPORTED_EXTENSIONS = {
    "md", "txt", "py", "sh", "js", "ts", "json",
    "purr", "game", "yaml", "yml", "toml", "rst",
    "csv", "xml", "html", "htm", "css", "pdf",
}

_SPLIT_SEPARATORS = ["\n\n", "\n", ". ", " ", ""]
_CHUNK_SIZE       = 500
_CHUNK_OVERLAP    = 80
_BINARY_CHECK_BYTES = 512


def _is_binary(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(_BINARY_CHECK_BYTES)
    except Exception:
        return True


def _read_file(path: str) -> str | None:
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, LookupError):
            continue
    return None


def _extract_heading(text: str, pos: int) -> str:
    """Return the last markdown heading (## ...) before position pos."""
    last = ""
    for line in text[:pos].splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            last = stripped
    return last


def _recursive_split(text: str, separators: list, chunk_size: int, overlap: int) -> list[str]:
    if not text:
        return []

    # Find the first separator that actually exists in text
    sep = ""
    remaining_seps = []
    for i, s in enumerate(separators):
        if s == "" or s in text:
            sep = s
            remaining_seps = separators[i + 1:]
            break

    if sep == "":
        # Base case: split by character
        chunks = []
        for start in range(0, len(text), chunk_size - overlap):
            chunks.append(text[start:start + chunk_size])
            if start + chunk_size >= len(text):
                break
        return chunks

    parts = text.split(sep)
    chunks = []
    current = ""

    for part in parts:
        candidate = current + (sep if current else "") + part
        if len(candidate) <= chunk_size:
            current = candidate
        else:
            if current:
                chunks.append(current.strip())
            if len(part) > chunk_size:
                # Recurse with next separator
                sub = _recursive_split(part, remaining_seps, chunk_size, overlap)
                chunks.extend(sub)
                current = sub[-1] if sub else ""
            else:
                current = part

    if current.strip():
        chunks.append(current.strip())

    # Apply overlap: prepend tail of previous chunk to next
    if overlap > 0 and len(chunks) > 1:
        overlapped = [chunks[0]]
        for i in range(1, len(chunks)):
            tail = chunks[i - 1][-overlap:]
            overlapped.append(tail + " " + chunks[i])
        chunks = overlapped

    return [c for c in chunks if c.strip()]


def _chunk_pdf(abs_path: str, kb_root: str) -> list[dict]:
    """Extract text from a PDF via PyMuPDF and return chunks with page metadata."""
    try:
        import fitz
    except ImportError:
        return []

    try:
        doc = fitz.open(abs_path)
    except Exception:
        return []

    try:
        rel_path = os.path.relpath(abs_path, kb_root)
    except ValueError:
        rel_path = abs_path

    file_modified = 0.0
    try:
        file_modified = os.path.getmtime(abs_path)
    except OSError:
        pass

    # Extract text per page, keep page number
    pages = []
    try:
        for page_num in range(len(doc)):
            try:
                text = doc[page_num].get_text()
                if text.strip():
                    pages.append((page_num + 1, text))
            except Exception:
                continue
    finally:
        doc.close()

    if not pages:
        return []

    # Chunk each page and tag with page number
    all_chunks = []
    for page_num, text in pages:
        raw = _recursive_split(text, _SPLIT_SEPARATORS, _CHUNK_SIZE, _CHUNK_OVERLAP)
        for chunk_text in raw:
            if chunk_text.strip():
                all_chunks.append((page_num, chunk_text))

    if not all_chunks:
        return []

    total = len(all_chunks)
    return [
        {
            "text": chunk_text,
            "metadata": {
                "source":        rel_path,
                "filename":      os.path.basename(abs_path),
                "extension":     "pdf",
                "chunk_index":   i,
                "chunk_total":   total,
                "file_modified": file_modified,
                "heading":       f"page {page_num}",
            },
        }
        for i, (page_num, chunk_text) in enumerate(all_chunks)
    ]


def chunk_file(abs_path: str, kb_root: str) -> list[dict]:
    """
    Chunk a single file and return a list of chunk dicts:
      {
        "text":     str,
        "metadata": {
            "source":        str,   # relative to kb_root
            "filename":      str,
            "extension":     str,
            "chunk_index":   int,
            "chunk_total":   int,
            "file_modified": float,
            "heading":       str,   # last ## heading before chunk (md only)
        }
      }
    Returns empty list if file is unsupported, binary, or unreadable.
    """
    ext = os.path.splitext(abs_path)[1].lstrip(".").lower()
    # Allow no-extension files
    if ext and ext not in SUPPORTED_EXTENSIONS:
        return []

    # PDF: dedicated extractor (binary file — must bypass binary check)
    if ext == "pdf":
        return _chunk_pdf(abs_path, kb_root)

    if _is_binary(abs_path):
        return []

    text = _read_file(abs_path)
    if not text or not text.strip():
        return []

    # Python: prefer function/class boundaries first
    if ext == "py":
        separators = ["\nclass ", "\ndef ", "\n\n", "\n", ". ", " ", ""]
    else:
        separators = _SPLIT_SEPARATORS

    raw_chunks = _recursive_split(text, separators, _CHUNK_SIZE, _CHUNK_OVERLAP)
    if not raw_chunks:
        return []

    try:
        rel_path = os.path.relpath(abs_path, kb_root)
    except ValueError:
        rel_path = abs_path

    file_modified = 0.0
    try:
        file_modified = os.path.getmtime(abs_path)
    except OSError:
        pass

    is_md = ext == "md"
    results = []

    # Pre-compute character offsets for heading extraction (markdown only)
    char_positions = []
    if is_md:
        pos = 0
        for chunk in raw_chunks:
            # Find this chunk roughly in original text
            idx = text.find(chunk[:50].strip(), pos)
            char_positions.append(idx if idx >= 0 else pos)
            pos = max(pos, idx + 1) if idx >= 0 else pos

    total = len(raw_chunks)
    for i, chunk_text in enumerate(raw_chunks):
        heading = ""
        if is_md and i < len(char_positions):
            heading = _extract_heading(text, char_positions[i])

        results.append({
            "text": chunk_text,
            "metadata": {
                "source":        rel_path,
                "filename":      os.path.basename(abs_path),
                "extension":     ext or "noext",
                "chunk_index":   i,
                "chunk_total":   total,
                "file_modified": file_modified,
                "heading":       heading,
            },
        })

    return results

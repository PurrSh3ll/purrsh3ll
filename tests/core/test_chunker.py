"""Tests for the RAG text chunker (core/rag/chunker.py).

Covers the pure text-splitting logic and the chunk_file front door: separator
selection, overlap, markdown heading extraction, metadata shape, and the
unsupported/binary/empty short-circuits. PDF handling (_chunk_pdf) needs PyMuPDF
and is out of scope here.
"""

from core.rag import chunker


# --------------------------------------------------------------------------- #
# _recursive_split
# --------------------------------------------------------------------------- #
def test_split_empty_text_returns_empty_list():
    assert chunker._recursive_split("", chunker._SPLIT_SEPARATORS, 500, 80) == []


def test_split_short_text_is_single_chunk():
    out = chunker._recursive_split("hello world", chunker._SPLIT_SEPARATORS, 500, 80)
    assert out == ["hello world"]


def test_split_breaks_on_paragraph_boundary():
    text = "aaa\n\nbbb\n\nccc"
    out = chunker._recursive_split(text, chunker._SPLIT_SEPARATORS, 10, 0)
    assert out == ["aaa\n\nbbb", "ccc"]


def test_split_applies_overlap_prefix():
    text = "aaa\n\nbbb\n\nccc"
    out = chunker._recursive_split(text, chunker._SPLIT_SEPARATORS, 10, 3)
    # Two chunks; the second is prefixed with the tail of the first.
    assert len(out) == 2
    assert out[0] == "aaa\n\nbbb"
    assert out[1].startswith("bbb ")


def test_split_never_yields_blank_chunks():
    text = "word " * 400  # forces multiple chunks
    out = chunker._recursive_split(text, chunker._SPLIT_SEPARATORS, 100, 20)
    assert len(out) > 1
    assert all(c.strip() for c in out)


# --------------------------------------------------------------------------- #
# _extract_heading
# --------------------------------------------------------------------------- #
def test_extract_heading_returns_last_heading_before_pos():
    text = "# Title\nsome text\n## Section\nmore text here"
    assert chunker._extract_heading(text, len(text)) == "## Section"


def test_extract_heading_earlier_position_sees_only_earlier_heading():
    text = "# Title\nsome text\n## Section\nmore text here"
    pos = text.index("## Section")
    assert chunker._extract_heading(text, pos) == "# Title"


def test_extract_heading_none_before_pos():
    assert chunker._extract_heading("plain text no heading", 5) == ""


# --------------------------------------------------------------------------- #
# _is_binary / _read_file
# --------------------------------------------------------------------------- #
def test_is_binary_true_for_null_bytes(tmp_path):
    f = tmp_path / "b.bin"
    f.write_bytes(b"abc\x00def")
    assert chunker._is_binary(str(f)) is True


def test_is_binary_false_for_text(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("just text")
    assert chunker._is_binary(str(f)) is False


# --------------------------------------------------------------------------- #
# chunk_file
# --------------------------------------------------------------------------- #
def test_chunk_file_unsupported_extension_returns_empty(tmp_path):
    f = tmp_path / "data.xyz"
    f.write_text("content that would otherwise chunk fine")
    assert chunker.chunk_file(str(f), str(tmp_path)) == []


def test_chunk_file_binary_returns_empty(tmp_path):
    f = tmp_path / "note.txt"
    f.write_bytes(b"text\x00more")
    assert chunker.chunk_file(str(f), str(tmp_path)) == []


def test_chunk_file_empty_returns_empty(tmp_path):
    f = tmp_path / "empty.md"
    f.write_text("   \n  ")
    assert chunker.chunk_file(str(f), str(tmp_path)) == []


def test_chunk_file_markdown_metadata_shape(tmp_path):
    f = tmp_path / "doc.md"
    body = "# Heading\n\n" + ("Some prose paragraph. " * 60)
    f.write_text(body)

    chunks = chunker.chunk_file(str(f), str(tmp_path))
    assert len(chunks) >= 1

    total = len(chunks)
    for i, ch in enumerate(chunks):
        md = ch["metadata"]
        assert ch["text"].strip()
        assert md["source"] == "doc.md"          # relative to kb_root
        assert md["filename"] == "doc.md"
        assert md["extension"] == "md"
        assert md["chunk_index"] == i
        assert md["chunk_total"] == total
        assert isinstance(md["file_modified"], float)
        assert "heading" in md


def test_chunk_file_respects_allowed_ext_override(tmp_path):
    f = tmp_path / "script.py"
    f.write_text("def foo():\n    return 1\n")
    # Default set excludes .py, so without an override we get nothing...
    assert chunker.chunk_file(str(f), str(tmp_path)) == []
    # ...but explicitly allowing py produces chunks.
    chunks = chunker.chunk_file(str(f), str(tmp_path), allowed_ext={"py"})
    assert len(chunks) >= 1
    assert chunks[0]["metadata"]["extension"] == "py"

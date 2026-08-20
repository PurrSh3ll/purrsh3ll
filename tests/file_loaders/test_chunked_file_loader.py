"""Tests for the chunked large-file writer (file_loaders.chunked_file_loader).

_write_chunks_to_disk assembles chunks and writes them atomically (temp file +
fsync + os.replace) while preserving the target's permissions and timestamps,
leaving no temp litter behind. _cleanup_thread drops a finished thread's
reference so it can be garbage-collected. Both are pure (no GUI) and are exactly
the "does it write big files safely / free resources" path.
"""

import glob
import os
import stat
import time

from file_loaders.chunked_file_loader import ChunkedFileLoader


def _loader():
    return ChunkedFileLoader()


# --------------------------------------------------------------------------- #
# _write_chunks_to_disk — content
# --------------------------------------------------------------------------- #
def test_writes_joined_chunks_to_new_file(tmp_path):
    path = str(tmp_path / "out.txt")
    _loader()._write_chunks_to_disk(["hello ", "big ", "world"], path)
    with open(path, encoding="utf-8") as f:
        assert f.read() == "hello big world"


def test_overwrites_existing_file_content(tmp_path):
    p = tmp_path / "out.txt"
    p.write_text("old content")
    _loader()._write_chunks_to_disk(["brand ", "new"], str(p))
    assert p.read_text() == "brand new"


def test_writes_unicode_correctly(tmp_path):
    p = tmp_path / "u.txt"
    _loader()._write_chunks_to_disk(["cześć ", "мир ", "🌍"], str(p))
    assert p.read_text(encoding="utf-8") == "cześć мир 🌍"


def test_writes_large_content_intact(tmp_path):
    p = tmp_path / "big.txt"
    chunks = [f"line {i}\n" for i in range(200_000)]      # ~2.5 MB across many chunks
    _loader()._write_chunks_to_disk(chunks, str(p))
    expected = "".join(chunks)
    data = p.read_text()
    assert len(data) == len(expected)
    assert data == expected


# --------------------------------------------------------------------------- #
# _write_chunks_to_disk — atomicity / no litter
# --------------------------------------------------------------------------- #
def test_leaves_no_temp_files_behind(tmp_path):
    p = tmp_path / "out.txt"
    _loader()._write_chunks_to_disk(["some ", "data"], str(p))
    leftovers = glob.glob(str(tmp_path / ".tmp_write_*"))
    assert leftovers == []
    # Only the target file should exist in the dir.
    assert os.listdir(tmp_path) == ["out.txt"]


# --------------------------------------------------------------------------- #
# _write_chunks_to_disk — metadata preservation
# --------------------------------------------------------------------------- #
def test_preserves_file_permissions(tmp_path):
    p = tmp_path / "secret.txt"
    p.write_text("orig")
    os.chmod(p, 0o600)
    _loader()._write_chunks_to_disk(["new secret"], str(p))
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode == 0o600


def test_preserves_modification_time(tmp_path):
    p = tmp_path / "stamped.txt"
    p.write_text("orig")
    old = time.time() - 100_000
    os.utime(p, (old, old))
    _loader()._write_chunks_to_disk(["updated"], str(p))
    assert abs(os.stat(p).st_mtime - old) < 2      # restored, not "now"


# --------------------------------------------------------------------------- #
# _cleanup_thread — reference release
# --------------------------------------------------------------------------- #
def test_cleanup_removes_thread_reference():
    ref = object()
    threads = ["a", ref, "b"]
    _loader()._cleanup_thread(threads, ref)
    assert ref not in threads
    assert threads == ["a", "b"]


def test_cleanup_removes_all_duplicate_references():
    ref = object()
    threads = [ref, "x", ref, ref]
    _loader()._cleanup_thread(threads, ref)
    assert ref not in threads
    assert threads == ["x"]


def test_cleanup_missing_reference_is_noop():
    threads = ["a", "b"]
    _loader()._cleanup_thread(threads, object())
    assert threads == ["a", "b"]


def test_cleanup_handles_none_list():
    _loader()._cleanup_thread(None, object())   # must not raise

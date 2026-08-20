"""Tests for the toolkit MCP server's write_file tool.

Focus: the "never overwrite" guarantee. A fresh write to an existing path must
pick a numbered variant (``report (1).txt``) instead of clobbering the file, and
the tool must report back the name it actually used. ``append=true`` keeps
targeting the exact path.
"""

import os

import toolkit_server as tk


# --------------------------------------------------------------------------- #
# _unique_path — the core rename logic
# --------------------------------------------------------------------------- #
def test_unique_path_returns_input_when_free(tmp_path):
    target = str(tmp_path / "notes.txt")
    assert tk._unique_path(target) == target


def test_unique_path_adds_suffix_before_extension(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("x")
    assert tk._unique_path(str(target)) == str(tmp_path / "notes (1).txt")


def test_unique_path_increments_until_free(tmp_path):
    (tmp_path / "notes.txt").write_text("x")
    (tmp_path / "notes (1).txt").write_text("x")
    (tmp_path / "notes (2).txt").write_text("x")
    assert tk._unique_path(str(tmp_path / "notes.txt")) == str(tmp_path / "notes (3).txt")


def test_unique_path_handles_no_extension(tmp_path):
    target = tmp_path / "README"
    target.write_text("x")
    assert tk._unique_path(str(target)) == str(tmp_path / "README (1)")


# --------------------------------------------------------------------------- #
# _tool_write_file — end to end
# --------------------------------------------------------------------------- #
def test_write_creates_file_and_reports_path(tmp_path):
    target = tmp_path / "out.txt"
    msg = tk._tool_write_file({"path": str(target), "content": "hello"})
    assert target.read_text() == "hello"
    assert str(target) in msg
    assert "wrote" in msg


def test_write_never_overwrites_existing(tmp_path):
    target = tmp_path / "out.txt"
    tk._tool_write_file({"path": str(target), "content": "first"})
    msg = tk._tool_write_file({"path": str(target), "content": "second"})

    # Original untouched, second write landed on the "(1)" variant.
    assert target.read_text() == "first"
    variant = tmp_path / "out (1).txt"
    assert variant.read_text() == "second"
    # The returned message carries the real filename the model should use.
    assert str(variant) in msg


def test_repeated_writes_produce_numbered_series(tmp_path):
    target = tmp_path / "scan.txt"
    for content in ("a", "b", "c"):
        tk._tool_write_file({"path": str(target), "content": content})

    assert (tmp_path / "scan.txt").read_text() == "a"
    assert (tmp_path / "scan (1).txt").read_text() == "b"
    assert (tmp_path / "scan (2).txt").read_text() == "c"


def test_append_targets_exact_path_not_a_variant(tmp_path):
    target = tmp_path / "log.txt"
    tk._tool_write_file({"path": str(target), "content": "line1\n"})
    msg = tk._tool_write_file({"path": str(target), "content": "line2\n", "append": True})

    assert target.read_text() == "line1\nline2\n"
    assert "appended to" in msg
    # No numbered variant should have been created by the append.
    assert not (tmp_path / "log (1).txt").exists()


def test_write_creates_missing_parent_dirs(tmp_path):
    target = tmp_path / "nested" / "deep" / "file.txt"
    tk._tool_write_file({"path": str(target), "content": "data"})
    assert target.read_text() == "data"


def test_file_path_alias_is_accepted(tmp_path):
    target = tmp_path / "aliased.txt"
    tk._tool_write_file({"file_path": str(target), "content": "ok"})
    assert target.read_text() == "ok"


# --------------------------------------------------------------------------- #
# input validation
# --------------------------------------------------------------------------- #
def test_missing_path_raises(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        tk._tool_write_file({"content": "x"})


def test_non_string_content_raises(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        tk._tool_write_file({"path": str(tmp_path / "x.txt"), "content": 123})

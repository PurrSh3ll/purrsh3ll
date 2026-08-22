"""Tests for the toolkit MCP server's write_file tool.

Two guarantees: a fresh write never clobbers a PRE-EXISTING file (it picks a
numbered variant like ``report (1).txt`` and reports the real name), but writing
again to a file created EARLIER THIS SESSION replaces it in place — so a weak
model that writes a placeholder first and the real content second ends up with
one correct file, not a split. ``append=true`` always targets the exact path.
"""

import os

import pytest

import toolkit_server as tk


@pytest.fixture(autouse=True)
def _fresh_session():
    # write_file tracks the paths it created this session (module-level state);
    # reset it around every test so cases don't leak into one another.
    tk._SESSION_CREATED.clear()
    yield
    tk._SESSION_CREATED.clear()


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


def test_write_does_not_clobber_preexisting_file(tmp_path):
    # A file that existed BEFORE this session (written directly, not via the tool)
    # must never be overwritten — the write lands on a "(1)" variant.
    target = tmp_path / "out.txt"
    target.write_text("user's original data")
    msg = tk._tool_write_file({"path": str(target), "content": "agent output"})

    assert target.read_text() == "user's original data"    # untouched
    variant = tmp_path / "out (1).txt"
    assert variant.read_text() == "agent output"
    assert str(variant) in msg                             # real name reported


def test_rewriting_a_session_file_replaces_it(tmp_path):
    # The placeholder-then-real pattern: both writes target the same path, and the
    # file was created THIS session, so the second write replaces the first.
    target = tmp_path / "results.txt"
    tk._tool_write_file({"path": str(target), "content": "[results will appear here]"})
    msg = tk._tool_write_file({"path": str(target), "content": "real scan output"})

    assert target.read_text() == "real scan output"        # replaced in place
    assert not (tmp_path / "results (1).txt").exists()      # no split
    assert str(target) in msg


def test_repeated_session_writes_keep_one_file(tmp_path):
    target = tmp_path / "scan.txt"
    for content in ("a", "b", "c"):
        tk._tool_write_file({"path": str(target), "content": content})

    assert (tmp_path / "scan.txt").read_text() == "c"       # last write wins
    assert not (tmp_path / "scan (1).txt").exists()
    assert not (tmp_path / "scan (2).txt").exists()


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

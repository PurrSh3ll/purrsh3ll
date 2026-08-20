"""Tests for psfix's pure helpers (psfix).

Covers the bits that shape what gets injected into the model prompt when a
command fails: head/tail trimming of large output, extraction of the corrected
command from a model reply (stripping fences and <think> blocks), and the ps*
tool help-injection routing (module `-h` vs .zsh heredoc, size cap, fail-safe).
No subprocess is spawned for the routing tests — the two help sources are
monkeypatched — so these stay fast and CI-safe.
"""

import psfix


# --------------------------------------------------------------------------- #
# _trim_output_head_tail
# --------------------------------------------------------------------------- #
def test_trim_leaves_short_output_untouched():
    assert psfix._trim_output_head_tail("small", 100) == "small"


def test_trim_boundary_equal_length_untouched():
    text = "x" * 50
    assert psfix._trim_output_head_tail(text, 50) == text


def test_trim_keeps_head_and_tail_with_marker():
    out = "A" * 10_000
    trimmed = psfix._trim_output_head_tail(out, 1000)
    assert trimmed.startswith("A" * 600)      # 60% head
    assert trimmed.endswith("A" * 400)        # 40% tail
    assert "9,000 chars omitted" in trimmed    # omitted count, thousands-formatted


# --------------------------------------------------------------------------- #
# _clean_command
# --------------------------------------------------------------------------- #
def test_clean_strips_code_fence():
    assert psfix._clean_command("```\nls -la\n```") == "ls -la"


def test_clean_strips_think_block():
    text = "<think>\nI should suggest a listing\n</think>\nls -la"
    assert psfix._clean_command(text) == "ls -la"


def test_clean_strips_surrounding_backticks():
    assert psfix._clean_command("The fix is:\n`sudo apt update`") == "sudo apt update"


def test_clean_returns_last_command_after_prose():
    text = "The old command was wrong.\nnmap -sV 10.10.10.5"
    assert psfix._clean_command(text) == "nmap -sV 10.10.10.5"


def test_clean_returns_last_of_several_candidates():
    assert psfix._clean_command("cat a.txt\ncat b.txt") == "cat b.txt"


def test_clean_falls_back_to_last_nonempty_line_when_all_prose():
    # Every line is filtered as prose, so the fallback returns the last raw line.
    assert psfix._clean_command("Use the tool") == "Use the tool"


# --------------------------------------------------------------------------- #
# _pstool_help — routing (module vs zsh), cap, fail-safe
# --------------------------------------------------------------------------- #
def test_pstool_help_routes_module_tool(monkeypatch):
    monkeypatch.setattr(psfix, "_module_help", lambda m: f"MODULE:{m}")
    monkeypatch.setattr(psfix, "_zsh_help", lambda n, w: f"ZSH:{n}:{w}")
    assert psfix._pstool_help("psfix --something", ".") == "MODULE:psfix.py"


def test_pstool_help_routes_zsh_tool(monkeypatch):
    monkeypatch.setattr(psfix, "_module_help", lambda m: f"MODULE:{m}")
    monkeypatch.setattr(psfix, "_zsh_help", lambda n, w: f"ZSH:{n}:{w}")
    assert psfix._pstool_help("psask how do I x", ".") == "ZSH:psask:psai.zsh"


def test_pstool_help_uses_basename_of_path(monkeypatch):
    monkeypatch.setattr(psfix, "_module_help", lambda m: f"MODULE:{m}")
    assert psfix._pstool_help("/usr/local/bin/pshunter 10.10.10.5", ".") == "MODULE:pshunter.py"


def test_pstool_help_none_for_non_pstool():
    assert psfix._pstool_help("ls -la", ".") is None


def test_pstool_help_none_for_empty():
    assert psfix._pstool_help("", ".") is None


def test_pstool_help_caps_length(monkeypatch):
    monkeypatch.setattr(psfix, "_module_help", lambda m: "X" * 5000)
    out = psfix._pstool_help("psview file", ".")
    assert len(out) == psfix._PSTOOL_HELP_CAP


def test_pstool_help_none_when_source_empty(monkeypatch):
    monkeypatch.setattr(psfix, "_module_help", lambda m: None)
    assert psfix._pstool_help("psreport", ".") is None


# --------------------------------------------------------------------------- #
# _module_help / _zsh_help — real, no subprocess for zsh
# --------------------------------------------------------------------------- #
def test_module_help_missing_module_returns_none():
    assert psfix._module_help("this_module_does_not_exist.py") is None


def test_zsh_help_extracts_heredoc_from_real_wrapper():
    # psai.zsh defines psask() with a `cat <<'EOF' … EOF` help block.
    text = psfix._zsh_help("psask", "psai.zsh")
    assert text is not None
    assert isinstance(text, str) and text.strip()


def test_zsh_help_unknown_function_returns_none():
    assert psfix._zsh_help("no_such_fn", "psai.zsh") is None


def test_zsh_help_missing_wrapper_returns_none():
    assert psfix._zsh_help("psask", "nonexistent_wrapper.zsh") is None

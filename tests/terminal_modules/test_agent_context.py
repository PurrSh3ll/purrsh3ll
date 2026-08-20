"""Tests for purragent's context-window budgeting/trimming (agent_context).

A tool loop only appends to its transcript, so on a small window it would
overflow mid-run. Before each model call trim_agent_msgs shrinks it to fit while
preserving the system(+history) preamble and never orphaning a tool result.
These pin the grouping, char accounting, budget maths and all three trim tiers.
Pure functions — no model, no network.
"""

import json

import agent_context as ac


# --------------------------------------------------------------------------- #
# split_msg_groups
# --------------------------------------------------------------------------- #
def test_split_empty():
    assert ac.split_msg_groups([]) == []


def test_split_groups_assistant_with_its_tool_results():
    tail = [
        {"role": "assistant", "content": "a1"},
        {"role": "tool", "content": "r1"},
        {"role": "tool", "content": "r1b"},
        {"role": "assistant", "content": "a2"},
        {"role": "tool", "content": "r2"},
    ]
    groups = ac.split_msg_groups(tail)
    assert len(groups) == 2
    assert [m["content"] for m in groups[0]] == ["a1", "r1", "r1b"]
    assert [m["content"] for m in groups[1]] == ["a2", "r2"]


def test_split_leading_non_assistant_starts_a_group():
    groups = ac.split_msg_groups([{"role": "tool", "content": "x"},
                                  {"role": "tool", "content": "y"}])
    assert len(groups) == 1
    assert [m["content"] for m in groups[0]] == ["x", "y"]


# --------------------------------------------------------------------------- #
# msgs_chars
# --------------------------------------------------------------------------- #
def test_msgs_chars_counts_content():
    assert ac.msgs_chars([{"content": "abc"}, {"content": "de"}]) == 5


def test_msgs_chars_handles_missing_content():
    assert ac.msgs_chars([{"role": "assistant"}]) == 0


def test_msgs_chars_includes_tool_calls():
    tc = [{"id": "1"}]
    msg = {"role": "assistant", "content": "hi", "tool_calls": tc}
    assert ac.msgs_chars([msg]) == 2 + len(json.dumps(tc, default=str))


# --------------------------------------------------------------------------- #
# msgs_budget_chars
# --------------------------------------------------------------------------- #
def test_budget_none_when_window_unknown():
    assert ac.msgs_budget_chars(0, []) is None
    assert ac.msgs_budget_chars(None, []) is None


def test_budget_formula_without_schemas():
    # int(maxc*4*FILL_FRAC) - AGENT_OUTPUT_RESERVE_TOK*4 - schema_chars(=2 for "[]")
    expected = int(10000 * 4 * ac.FILL_FRAC) - ac.AGENT_OUTPUT_RESERVE_TOK * 4 - len("[]")
    assert ac.msgs_budget_chars(10000, []) == expected


def test_budget_shrinks_with_schemas():
    small = ac.msgs_budget_chars(10000, [{"name": "a" * 500}])
    big = ac.msgs_budget_chars(10000, [])
    assert small < big


def test_budget_never_negative():
    assert ac.msgs_budget_chars(1, []) == 0


# --------------------------------------------------------------------------- #
# trim_agent_msgs — guards
# --------------------------------------------------------------------------- #
def test_trim_noop_when_budget_none():
    msgs = [{"role": "system", "content": "s"}]
    assert ac.trim_agent_msgs(msgs, None) is False
    assert msgs == [{"role": "system", "content": "s"}]


def test_trim_noop_when_under_budget():
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "hi"}]
    before = [dict(m) for m in msgs]
    assert ac.trim_agent_msgs(msgs, 10_000) is False
    assert msgs == before


# --------------------------------------------------------------------------- #
# trim_agent_msgs — tiers
# --------------------------------------------------------------------------- #
def _convo(big_old_tool=3000):
    return [
        {"role": "system", "content": "S"},                 # preamble[0]
        {"role": "user", "content": "H"},                   # preamble[1]
        {"role": "assistant", "content": "a1"},             # group1 (oldest)
        {"role": "tool", "content": "X" * big_old_tool},    # group1 big result
        {"role": "assistant", "content": "a2"},             # group2
        {"role": "tool", "content": "r2"},
        {"role": "assistant", "content": "a3"},             # group3
        {"role": "tool", "content": "r3"},
        {"role": "assistant", "content": "a4"},             # group4 (newest)
        {"role": "tool", "content": "r4"},
    ]


def test_trim_tier1_blanks_old_tool_output():
    msgs = _convo()
    trimmed = ac.trim_agent_msgs(msgs, 300)     # budget big enough that tier1 suffices
    assert trimmed is True
    # oldest group's tool body replaced with the placeholder…
    assert msgs[3]["content"] == ac.AGENT_TRIM_PLACEHOLDER
    # …newer results untouched, preamble intact.
    assert msgs[5]["content"] == "r2"
    assert msgs[0]["content"] == "S" and msgs[1]["content"] == "H"


def test_trim_tier2_drops_oldest_group():
    msgs = _convo()
    trimmed = ac.trim_agent_msgs(msgs, 50)      # too tight for tier1 alone
    assert trimmed is True
    contents = [m.get("content") for m in msgs]
    # oldest group (a1 + its tool) dropped; last 3 groups kept.
    assert "a1" not in contents
    assert "a4" in contents and "r4" in contents
    # preamble always kept.
    assert msgs[0]["content"] == "S" and msgs[1]["content"] == "H"


def test_trim_last_resort_hard_caps_a_tool_body():
    # Only 3 groups (tier2 can't drop below KEEP_LAST), one huge newest tool body.
    msgs = [
        {"role": "system", "content": "S"},
        {"role": "user", "content": "H"},
        {"role": "assistant", "content": "a1"}, {"role": "tool", "content": "r1"},
        {"role": "assistant", "content": "a2"}, {"role": "tool", "content": "r2"},
        {"role": "assistant", "content": "a3"}, {"role": "tool", "content": "X" * 5000},
    ]
    trimmed = ac.trim_agent_msgs(msgs, 4000)
    assert trimmed is True
    assert msgs[-1]["content"].endswith("[…truncated]")
    assert len(msgs[-1]["content"]) < 5000
    assert ac.msgs_chars(msgs) <= 4000

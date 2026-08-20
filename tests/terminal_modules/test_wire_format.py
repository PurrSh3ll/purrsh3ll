"""Tests for the OpenAI↔Anthropic wire-format converters (wire_format).

purragent keeps its transcript in OpenAI shape and translates to the Anthropic
Messages API at the wire for the anthropic provider. A bug here breaks every
Anthropic call (tool schemas, tool_use/tool_result blocks, system handling), so
these pin the conversion precisely. Pure functions — no network.
"""

import wire_format as wf


# --------------------------------------------------------------------------- #
# oai_tools_to_anthropic
# --------------------------------------------------------------------------- #
def test_converts_function_tool():
    tools = [{
        "type": "function",
        "function": {
            "name": "ping",
            "description": "check host",
            "parameters": {"type": "object", "properties": {"host": {"type": "string"}}},
        },
    }]
    out = wf.oai_tools_to_anthropic(tools)
    assert out == [{
        "name": "ping",
        "description": "check host",
        "input_schema": {"type": "object", "properties": {"host": {"type": "string"}}},
    }]


def test_tool_without_parameters_gets_empty_schema():
    tools = [{"type": "function", "function": {"name": "now"}}]
    out = wf.oai_tools_to_anthropic(tools)
    assert out[0]["input_schema"] == {"type": "object", "properties": {}}
    assert out[0]["description"] == ""


def test_bare_tool_dict_without_wrapper_is_accepted():
    # When t has no type=="function", the tool dict itself is used as the fn.
    tools = [{"name": "scan", "parameters": {"type": "object", "properties": {}}}]
    out = wf.oai_tools_to_anthropic(tools)
    assert out[0]["name"] == "scan"


def test_tool_without_name_is_skipped():
    tools = [{"type": "function", "function": {"description": "no name"}}]
    assert wf.oai_tools_to_anthropic(tools) == []


def test_empty_and_none_tools():
    assert wf.oai_tools_to_anthropic([]) == []
    assert wf.oai_tools_to_anthropic(None) == []


# --------------------------------------------------------------------------- #
# oai_msgs_to_anthropic — system handling
# --------------------------------------------------------------------------- #
def test_system_message_becomes_top_level_system():
    system, msgs = wf.oai_msgs_to_anthropic([{"role": "system", "content": "be nice"}])
    assert system == "be nice"
    assert msgs == []


def test_multiple_system_messages_joined():
    system, _ = wf.oai_msgs_to_anthropic([
        {"role": "system", "content": "rule one"},
        {"role": "system", "content": "rule two"},
    ])
    assert system == "rule one\n\nrule two"


def test_empty_system_content_ignored():
    system, _ = wf.oai_msgs_to_anthropic([{"role": "system", "content": ""}])
    assert system == ""


# --------------------------------------------------------------------------- #
# oai_msgs_to_anthropic — user / assistant
# --------------------------------------------------------------------------- #
def test_plain_user_message():
    _system, msgs = wf.oai_msgs_to_anthropic([{"role": "user", "content": "hi"}])
    assert msgs == [{"role": "user", "content": "hi"}]


def test_assistant_text_becomes_text_block():
    _system, msgs = wf.oai_msgs_to_anthropic([{"role": "assistant", "content": "hello"}])
    assert msgs == [{"role": "assistant", "content": [{"type": "text", "text": "hello"}]}]


def test_assistant_tool_call_becomes_tool_use():
    msgs = [{
        "role": "assistant",
        "content": "",
        "tool_calls": [{
            "id": "call_1",
            "function": {"name": "ping", "arguments": '{"host": "10.0.0.1"}'},
        }],
    }]
    _system, out = wf.oai_msgs_to_anthropic(msgs)
    block = out[0]["content"][0]
    assert block["type"] == "tool_use"
    assert block["id"] == "call_1"
    assert block["name"] == "ping"
    assert block["input"] == {"host": "10.0.0.1"}


def test_assistant_tool_call_with_bad_json_args_becomes_empty_input():
    msgs = [{
        "role": "assistant",
        "content": "",
        "tool_calls": [{"id": "c", "function": {"name": "x", "arguments": "{not json"}}],
    }]
    _system, out = wf.oai_msgs_to_anthropic(msgs)
    assert out[0]["content"][0]["input"] == {}


def test_assistant_with_text_and_tool_call_keeps_both_blocks():
    msgs = [{
        "role": "assistant",
        "content": "let me check",
        "tool_calls": [{"id": "c", "function": {"name": "ping", "arguments": "{}"}}],
    }]
    _system, out = wf.oai_msgs_to_anthropic(msgs)
    types = [b["type"] for b in out[0]["content"]]
    assert types == ["text", "tool_use"]


# --------------------------------------------------------------------------- #
# oai_msgs_to_anthropic — tool results
# --------------------------------------------------------------------------- #
def test_tool_result_becomes_user_tool_result_block():
    msgs = [{"role": "tool", "tool_call_id": "call_1", "content": "pong"}]
    _system, out = wf.oai_msgs_to_anthropic(msgs)
    assert out[0]["role"] == "user"
    block = out[0]["content"][0]
    assert block == {"type": "tool_result", "tool_use_id": "call_1", "content": "pong"}


def test_consecutive_tool_results_merge_into_one_user_turn():
    msgs = [
        {"role": "tool", "tool_call_id": "a", "content": "r1"},
        {"role": "tool", "tool_call_id": "b", "content": "r2"},
    ]
    _system, out = wf.oai_msgs_to_anthropic(msgs)
    assert len(out) == 1
    assert [b["tool_use_id"] for b in out[0]["content"]] == ["a", "b"]


def test_tool_result_does_not_merge_into_plain_user_turn():
    msgs = [
        {"role": "user", "content": "hi"},
        {"role": "tool", "tool_call_id": "a", "content": "r1"},
    ]
    _system, out = wf.oai_msgs_to_anthropic(msgs)
    assert len(out) == 2
    assert out[0] == {"role": "user", "content": "hi"}
    assert out[1]["content"][0]["type"] == "tool_result"


def test_internal_tr_marker_is_stripped_from_output():
    msgs = [{"role": "tool", "tool_call_id": "a", "content": "r1"}]
    _system, out = wf.oai_msgs_to_anthropic(msgs)
    assert all("_tr" not in m for m in out)


# --------------------------------------------------------------------------- #
# a fuller round-trip
# --------------------------------------------------------------------------- #
def test_full_conversation_shape():
    msgs = [
        {"role": "system", "content": "you are a scanner"},
        {"role": "user", "content": "scan 10.0.0.1"},
        {"role": "assistant", "content": "",
         "tool_calls": [{"id": "t1", "function": {"name": "ping", "arguments": '{"h":"10.0.0.1"}'}}]},
        {"role": "tool", "tool_call_id": "t1", "content": "alive"},
        {"role": "assistant", "content": "host is up"},
    ]
    system, out = wf.oai_msgs_to_anthropic(msgs)
    assert system == "you are a scanner"
    roles = [m["role"] for m in out]
    assert roles == ["user", "assistant", "user", "assistant"]
    # tool_use then tool_result then final text
    assert out[1]["content"][0]["type"] == "tool_use"
    assert out[2]["content"][0]["type"] == "tool_result"
    assert out[3]["content"][0]["text"] == "host is up"

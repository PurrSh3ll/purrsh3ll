"""purragent_core.graph — the agent core as a LangGraph state machine (Phase B).

This package is the Phase-B rebuild of purragent's hand-rolled ReAct loop
(``agent.query_model_with_tools``) into an explicit LangGraph ``StateGraph``:

    START -> call_model -> (tool_calls? & guards ok) -> tools -> call_model
                        \\-> END (final answer)

Design notes
------------
* **Serializable state only.** ``AgentState`` holds plain, JSON-serializable
  data (OpenAI-style message dicts, counters, the plan, the final answer) so it
  can be checkpointed by ``SqliteSaver`` and resumed. Non-serializable runtime
  dependencies — the live model call, the tool executor, the MCP manager,
  streaming callbacks — are passed per-invocation through
  ``config["configurable"]`` and never enter the checkpointed state.
* **Nodes delegate.** ``call_model`` and ``tools`` call injected callables
  (``model_caller`` / ``tool_runner``) pulled from the config, so the graph's
  control flow is unit-testable with fakes and the real providers/tools code is
  wired in by the integration layer (integration.py).
* **Guards** (``guards.py``) bound the loop: round ceiling and repeat/loop
  detection, mirroring the legacy loop's limits.

Status: this graph is now the agent's only execution path — the REPL calls
``integration.run_agent_graph`` for every turn. The former hand-rolled loop was
removed after legacy<->graph equivalence was proven (see git history: Phase B).
"""

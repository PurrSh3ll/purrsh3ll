"""purragent_core.graph.build — assemble and compile the agent graph.

    START -> call_model -> route ->  "tools" -> call_model   (loop)
                                 \\-> END                      (final answer)

Pass a checkpointer (e.g. ``SqliteSaver``) to make engagements resumable and to
support human-in-the-loop pauses; omit it for a stateless one-shot run.
"""

from langgraph.graph import END, START, StateGraph

from purragent_core.graph.nodes import (call_model_node, exec_tools_node,
                                         route_after_model, route_after_tools)
from purragent_core.graph.state import AgentState


def build_agent_graph(checkpointer=None):
    """Build and compile the agent StateGraph.

    The returned app is invoked with an initial state and a config carrying the
    runtime deps, e.g.::

        app.invoke(
            {"messages": [{"role": "user", "content": "..."}], "round": 0},
            config={"configurable": {
                "thread_id": "...",          # required when checkpointing
                "model_caller": model_caller,
                "tool_runner": tool_runner,
            }},
        )
    """
    graph = StateGraph(AgentState)
    graph.add_node("call_model", call_model_node)
    graph.add_node("tools", exec_tools_node)

    graph.add_edge(START, "call_model")
    graph.add_conditional_edges(
        "call_model",
        route_after_model,
        {"tools": "tools", END: END},
    )
    graph.add_conditional_edges(
        "tools",
        route_after_tools,
        {"call_model": "call_model", END: END},
    )

    return graph.compile(checkpointer=checkpointer)

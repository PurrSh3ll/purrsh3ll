"""purragent — interactive console agent for PurrSh3ll.

Claude-Code-style REPL that plans and works right in the terminal: a
general-purpose assistant and an autonomous hacking mode (/hack). Tools are
discovered on demand via RAG, so unlimited MCP servers connect without prompt
bloat; works with local and cloud models (OpenAI-compatible and native
Anthropic). Model/provider/key plumbing is reused from psai.py.

This package is the Phase-A decomposition of the former single-file
purragent.py (~8.6k lines) into cohesive, layered modules. Behaviour is
unchanged — code was moved verbatim, not rewritten:

    _shared     constants, prompts, console, leaf-module aliases
    ui          terminal rendering primitives (overlays, pickers, spinners)
    state       on-disk session state, memory & findings
    models      profiles, registry, capabilities, context budgeting
    providers   OpenAI-compatible & native-Anthropic streaming chat
    tools       tool catalog, resolution, RAG retriever, confirm gate
    chrome      model-aware UI (banner, model picker, context view)
    mcp         MCP server browser / doctor
    dbview      engagement target database browser
    agent       the tool-use loop + conversation summarise/recall
    hack        autonomous hacking-mode engine (recon -> exploitation)
    repl        the interactive shell + CLI entry (main)
"""

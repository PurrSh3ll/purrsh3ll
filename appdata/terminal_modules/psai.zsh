psai() {
    local _base="${${(%):-%x}:A:h:h:h}"
    local _py="$_base/.venv/bin/python3"
    local _script="$_base/appdata/terminal_modules/psai.py"

    if [[ ! -x "$_py" ]]; then
        _py="python3"
    fi

    if [[ ! -f "$_script" ]]; then
        echo "psai: script not found: $_script" >&2
        return 1
    fi

    "$_py" "$_script" --base-dir "$_base" "$@"
}

# PSDESC: ask the active AI profile a direct question
psask() {
    if [[ $# -eq 0 ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        cat <<'EOF'
psask — direct question to the active AI profile (no RAG context)

Usage:
  psask [options] <query>

Options:
  -p, --profile NAME   Use a specific saved profile by name
  -H, --host URL       Base URL override
  -r, --rag            Enrich prompt with RAG knowledge base context
  -n, --top-n N        Number of RAG chunks to retrieve (default: 5, requires --rag)
  -h, --help           Show this help

Examples:
  psask "what is XSS?"
  psask -p openai-gpt4o "explain SQL injection"
  psask -r "how to enumerate subdomains"
EOF
        return 0
    fi
    psai ask "$@"
}

# PSDESC: persistent chat session with the active AI profile
pschat() {
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        cat <<'EOF'
pschat — chat with persistent conversation history

Usage:
  pschat <message>           Send a message (history is preserved)
  pschat --history           Show current conversation history
  pschat --clear             Clear conversation history and exit
  pschat --new [message]     Clear history, optionally send first message

Options:
  -p, --profile NAME   Use a specific saved profile by name
  -H, --host URL       Base URL override
  -r, --rag            Enrich current message with RAG knowledge base context
  -n, --top-n N        Number of RAG chunks to retrieve (default: 5, requires --rag)
  -c, --clear          Clear conversation history and exit
  -h, --help           Show this help

Examples:
  pschat "explain SQL injection"
  pschat "what did we talk about?"
  pschat -r "what do my notes say about XSS?"
  pschat --new "start fresh: what is SSRF?"
  pschat --history
  pschat -c
EOF
        return 0
    fi
    psai chat "$@"
}

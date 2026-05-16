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

psask() {
    if [[ $# -eq 0 ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        cat <<'EOF'
psask — direct question to the active AI profile (no RAG context)

Usage:
  psask [options] <query>

Options:
  -m MODEL      Model override (default: from active profile)
  --host URL    Base URL override
  -h, --help    Show this help

Examples:
  psask "what is XSS?"
  psask -m gpt-4o "explain SQL injection"
EOF
        return 0
    fi
    psai ask "$@"
}

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
  -m MODEL      Model override (default: from active profile)
  --host URL    Base URL override
  -h, --help    Show this help

Examples:
  pschat "explain SQL injection"
  pschat "what did we talk about?"
  pschat --new "start fresh: what is SSRF?"
  pschat --history
  pschat --clear
EOF
        return 0
    fi
    psai chat "$@"
}

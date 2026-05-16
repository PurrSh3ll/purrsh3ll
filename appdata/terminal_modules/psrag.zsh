psrag() {
    if [[ $# -eq 0 ]] || [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        cat <<'EOF'
psrag — query the PurrSh3ll RAG knowledge base

Usage:
  psrag [options] <query>

Options:
  -n N             Number of context chunks to retrieve  (default: 5)
  -m MODEL         Model to use  (default: from active API profile)
  --host URL       Provider host/base URL override
  --no-context     Skip RAG — query model directly
  --show-sources   Print source filenames and scores before the answer
  -h, --help       Show this help

Examples:
  psrag "what is XSS?"
  psrag -n 3 --show-sources "how to enumerate subdomains"
  psrag -m llama3.2 "explain SQL injection"
  psrag --host http://192.168.1.10:11434 "query"
  psrag --no-context "what is 2+2"
EOF
        return 0
    fi

    local _base="${${(%):-%x}:A:h:h:h}"
    local _py="$_base/.venv/bin/python3"
    local _script="$_base/appdata/terminal_modules/psrag_query.py"

    if [[ ! -x "$_py" ]]; then
        _py="python3"
    fi

    if [[ ! -f "$_script" ]]; then
        echo "psrag: query script not found: $_script" >&2
        return 1
    fi

    "$_py" "$_script" --base-dir "$_base" "$@"
}

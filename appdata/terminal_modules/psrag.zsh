# PSDESC: query the RAG knowledge base with a natural language question
psrag() {
    if [[ $# -eq 0 ]] || [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        cat <<'EOF'
psrag — query the PurrSh3ll RAG knowledge base

Usage:
  psrag [options] <query>

Options:
  -n, --top-n N        Number of context chunks to retrieve (default: 5)
  -p, --profile NAME   Use a specific saved profile by name
  -H, --host URL       Provider host/base URL override
  -s, --show-sources   Print source filenames and scores before the answer
  -l, --list           List indexed documents and saved terminal fragments, then exit
  -h, --help           Show this help

Examples:
  psrag "what is XSS?"
  psrag -n 3 -s "how to enumerate subdomains"
  psrag -p my-ollama "explain SQL injection"
  psrag -H http://192.168.1.10:11434 "query"
  psrag -l
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

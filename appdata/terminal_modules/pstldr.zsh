pstldr() {
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        cat <<'EOF'
pstldr — AI-powered TL;DR summarizer

Usage:
  pstldr <file>            Summarize a file (first part if truncated)
  pstldr --tail <file>     Summarize a file (last part if truncated, useful for logs)
  pstldr "<text>"          Summarize text passed directly
  cat file | pstldr        Summarize piped input
  pstldr -m <model> <file> Use a specific model
EOF
        return 0
    fi

    local _base="${${(%):-%x}:A:h:h:h}"
    local _py="$_base/.venv/bin/python3"
    local _script="$_base/appdata/terminal_modules/pstldr.py"

    if [[ ! -x "$_py" ]]; then
        _py="python3"
    fi

    if [[ ! -f "$_script" ]]; then
        echo "pstldr: script not found: $_script" >&2
        return 1
    fi

    "$_py" "$_script" --base-dir "$_base" "$@"
}

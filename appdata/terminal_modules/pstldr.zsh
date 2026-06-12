# PSDESC: summarize the last command output with AI (TL;DR)
pstldr() {
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        cat <<'EOF'
pstldr — AI-powered TL;DR summarizer

Usage:
  pstldr <file>                Summarize a file
  pstldr --head [N] <file>     Send only the first N chars (default 4000)
  pstldr --tail [N] <file>     Send only the last N chars (default 4000, useful for logs)
  pstldr "<text>"              Summarize text passed directly
  cat file | pstldr            Summarize piped input
  pstldr -p <profile> <file>   Use a specific saved profile
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

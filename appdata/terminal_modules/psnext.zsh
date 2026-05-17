psnext() {
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        cat <<'EOF'
psnext — AI pentest next-step advisor

Usage:
  psnext                          Suggest next steps based on terminal history
  psnext --target <host/network>  Include target context in analysis

psnext reads the terminal session history and uses AI to summarize what
has been done, identify gaps, and suggest the most promising next moves.
EOF
        return 0
    fi

    local _base="${${(%):-%x}:A:h:h:h}"
    local _py="$_base/.venv/bin/python3"
    local _script="$_base/appdata/terminal_modules/psnext.py"

    if [[ ! -x "$_py" ]]; then
        _py="python3"
    fi

    if [[ ! -f "$_script" ]]; then
        echo "psnext: script not found: $_script" >&2
        return 1
    fi

    "$_py" "$_script" --base-dir "$_base" --cwd "$PWD" "$@"
}

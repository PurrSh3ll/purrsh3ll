# PSDESC: generate a shell command using AI from a natural language description
pscmd() {
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]] || [[ $# -eq 0 ]]; then
        cat <<'EOF'
pscmd — AI-powered shell command generator

Usage:
  pscmd <description>            Generate a shell command from natural-language description
  pscmd -m <model> <description> Use a specific model

Examples:
  pscmd list all open ports
  pscmd find files modified in the last 24 hours
  pscmd kill process using port 8080
  pscmd -m gpt-4o list all open ports
EOF
        return 0
    fi

    local _base="${${(%):-%x}:A:h:h:h}"
    local _py="$_base/.venv/bin/python3"
    local _script="$_base/appdata/terminal_modules/pscmd.py"

    if [[ ! -x "$_py" ]]; then
        _py="python3"
    fi

    if [[ ! -f "$_script" ]]; then
        echo "pscmd: script not found: $_script" >&2
        return 1
    fi

    # Stream AI output to terminal (via 2>/dev/tty), capture generated command on stdout
    local _cmd
    _cmd=$("$_py" "$_script" --base-dir "$_base" --cwd "$PWD" "$@" 2>/dev/tty)

    if [[ -n "$_cmd" ]]; then
        echo -n "Paste command? [y/n] " >/dev/tty
        read -r _reply </dev/tty
        if [[ "$_reply" == [yY] ]]; then
            print -z "$_cmd"
        fi
    fi
}

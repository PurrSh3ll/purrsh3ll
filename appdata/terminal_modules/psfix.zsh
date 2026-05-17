psfix() {
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        cat <<'EOF'
psfix — AI-powered terminal error explainer/fixer

Usage:
  psfix             Paste the corrected command at the prompt (ready to run)
  psfix --explain   Explain why the last command failed

psfix reads the last command from terminal history automatically.
It can also be triggered via the ⚠ Explain / 🔧 Fix overlay buttons
that appear in the terminal after a command fails.
EOF
        return 0
    fi

    local _base="${${(%):-%x}:A:h:h:h}"
    local _py="$_base/.venv/bin/python3"
    local _script="$_base/appdata/terminal_modules/psfix.py"

    if [[ ! -x "$_py" ]]; then
        _py="python3"
    fi

    if [[ ! -f "$_script" ]]; then
        echo "psfix: script not found: $_script" >&2
        return 1
    fi

    if [[ "$*" == *"--explain"* ]]; then
        # Explain mode: stream output normally to the terminal
        "$_py" "$_script" --base-dir "$_base" "$@"
    else
        # Fix mode: stream visible on stderr (2>/dev/tty), capture clean command on stdout
        local _fixed
        _fixed=$("$_py" "$_script" --base-dir "$_base" --paste-mode "$@" 2>/dev/tty)
        if [[ -n "$_fixed" ]]; then
            # Paste the corrected command into the ZLE input buffer without executing
            print -z "$_fixed"
        fi
    fi
}

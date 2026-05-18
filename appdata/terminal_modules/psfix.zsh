psfix() {
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        cat <<'EOF'
psfix — AI-powered terminal error explainer/fixer

Usage:
  psfix                  Paste the corrected command at the prompt (ready to run)
  psfix --explain        Explain why the last command failed
  psfix --analyze        Deep analysis using terminal history and working directory
  psfix -m <model>       Use a specific model

psfix reads the last command from terminal history automatically.
Triggered via the ⚠ Explain / 🔧 Fix / 🔍 Analyze overlay buttons
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
        # Explain mode: stream explanation to terminal (via 2>/dev/tty), capture fix command on stdout
        local _fix_cmd
        _fix_cmd=$("$_py" "$_script" --base-dir "$_base" "$@" 2>/dev/tty)
        if [[ -n "$_fix_cmd" ]]; then
            echo -n "Paste corrected command? [y/n] " >/dev/tty
            read -r _reply </dev/tty
            if [[ "$_reply" == [yY] ]]; then
                print -z "$_fix_cmd"
            fi
        fi
    elif [[ "$*" == *"--analyze"* ]]; then
        # Analyze mode: stream analysis to terminal (via 2>/dev/tty), capture fix command on stdout
        local _fix_cmd
        _fix_cmd=$("$_py" "$_script" --base-dir "$_base" "$@" 2>/dev/tty)
        if [[ -n "$_fix_cmd" ]]; then
            echo -n "Paste corrected command? [y/n] " >/dev/tty
            read -r _reply </dev/tty
            if [[ "$_reply" == [yY] ]]; then
                print -z "$_fix_cmd"
            fi
        fi
    else
        # Fix mode: capture clean command on stdout, paste into ZLE buffer
        local _fixed
        _fixed=$("$_py" "$_script" --base-dir "$_base" --paste-mode "$@" 2>/dev/tty)
        if [[ -n "$_fixed" ]]; then
            print -z "$_fixed"
        fi
    fi
}

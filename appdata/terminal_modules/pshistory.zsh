# PSDESC: query PurrSh3ll terminal history SQLite database
pshistory() {
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        cat <<'EOF'
pshistory — query PurrSh3ll terminal history SQLite database

Usage:
  pshistory                    show last 20 commands
  pshistory -n 50              show last 50 commands
  pshistory --all              show full history (all commands)
  pshistory -q nmap            search commands/output for 'nmap'
  pshistory --findings         show all findings
  pshistory --stats            show DB statistics
  pshistory --show 42          show full output of command id=42
  pshistory --clear            delete entire history (asks for confirmation)
  pshistory --clear -y         delete without confirmation prompt
  pshistory --db /path/to.db   use a custom DB path
EOF
        return 0
    fi

    local _base="${${(%):-%x}:A:h:h:h}"
    local _py="$_base/.venv/bin/python3"
    local _script="$_base/appdata/terminal_modules/pshistory.py"

    if [[ ! -x "$_py" ]]; then
        _py="python3"
    fi

    if [[ ! -f "$_script" ]]; then
        echo "pshistory: script not found: $_script" >&2
        return 1
    fi

    "$_py" "$_script" "$@"
}

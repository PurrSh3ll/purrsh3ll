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
  pshistory -t recon           show commands tagged as 'recon'
  pshistory -t web -n 50       show last 50 web commands
  pshistory -t exploit --all   show all exploitation commands
  pshistory --categories       list all available categories (tag + label + DB count)
  pshistory --targets          show all discovered targets (IPs / hostnames)
  pshistory --ports            show all open ports (all targets)
  pshistory --ports 10.10.10.1 show open ports for a specific target
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

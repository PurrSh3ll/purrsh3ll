# PSDESC: check external dependencies (tools, libraries, runtime paths)
pshealth() {
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        cat <<'EOF'
pshealth — check PurrSh3ll external dependencies

USAGE
  pshealth            status of tools, libraries and runtime paths
  pshealth --json     machine-readable JSON (for scripts)
  pshealth -h         this help

EXIT CODE
  0  all present   ·   1  something missing
EOF
        return 0
    fi

    local _base="${${(%):-%x}:A:h:h:h}"
    local _py="$_base/.venv/bin/python3"
    local _script="$_base/appdata/terminal_modules/pshealth.py"

    if [[ ! -x "$_py" ]]; then
        _py="python3"
    fi

    if [[ ! -f "$_script" ]]; then
        echo "pshealth: script not found: $_script" >&2
        return 1
    fi

    "$_py" "$_script" "$@"
}

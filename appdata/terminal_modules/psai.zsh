psai() {
    local _base="${${(%):-%x}:A:h:h:h}"
    local _py="$_base/.venv/bin/python3"
    local _script="$_base/appdata/terminal_modules/psai.py"

    if [[ ! -x "$_py" ]]; then
        _py="python3"
    fi

    if [[ ! -f "$_script" ]]; then
        echo "psai: script not found: $_script" >&2
        return 1
    fi

    "$_py" "$_script" --base-dir "$_base" "$@"
}

pschat() {
    psai chat "$@"
}

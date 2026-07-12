# Resolve this module's dir at source time (%x reliably points to this file then),
# so the command works regardless of the terminal's current directory.
_PSHUNTER_MODULES_DIR="${${(%):-%x}:A:h}"

# PSDESC: guided host-discovery / recon workflow (nmap engine, report screenshots)
pshunter() {
    local _base="${_PSHUNTER_MODULES_DIR:h:h}"        # app root (parent of appdata/)
    local _py="$_base/.venv/bin/python3"
    local _script="$_PSHUNTER_MODULES_DIR/pshunter.py"

    [[ -x "$_py" ]] || _py="python3"
    if [[ ! -f "$_script" ]]; then
        echo "pshunter: script not found: $_script" >&2
        return 1
    fi

    # Interactive TUI: run in the foreground, passing through stdin/stdout and args.
    "$_py" "$_script" "$@"
}

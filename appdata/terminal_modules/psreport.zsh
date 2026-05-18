psreport() {
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        cat <<'EOF'
psreport — AI-powered pentest report generator

Usage:
  psreport                              Generate report, save only (silent)
  psreport --deep                       Map-Reduce: chunk full history, thorough analysis
  psreport --verbose                    Stream report to terminal while saving
  psreport --format html                Generate HTML report (default: md)
  psreport --full                       Include full history (no smart filter)
  psreport --target <host/network>      Set target in report header
  psreport --title "<title>"            Set custom report title
  psreport -m <model>                   Use a specific model

--deep prompts for confirmation before sending N+1 requests to the model.
Report is saved to appmodules/Cyb3rCollector/reports/report_YYYY-MM-DD_HH-MM.{md,html}
EOF
        return 0
    fi

    local _base="${${(%):-%x}:A:h:h:h}"
    local _py="$_base/.venv/bin/python3"
    local _script="$_base/appdata/terminal_modules/psreport.py"

    if [[ ! -x "$_py" ]]; then
        _py="python3"
    fi

    if [[ ! -f "$_script" ]]; then
        echo "psreport: script not found: $_script" >&2
        return 1
    fi

    "$_py" "$_script" --base-dir "$_base" --cwd "$PWD" "$@"
}

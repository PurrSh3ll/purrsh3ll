# PSDESC: generate a pentest report from terminal history using AI
psreport() {
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        cat <<'EOF'
psreport — AI-powered pentest report generator

Usage:
  psreport                                    Generate report from full filtered history
  psreport -L, --limit N                      Last N commands per phase (recon/scan/exploit/…) — balanced coverage
  psreport -N, --nano                         Nano: section-by-section generation (4K context models)
  psreport -n, --notes FILE                   Notes mode: report from your notes + terminal evidence
  psreport -v, --verbose                      Stream synthesis to terminal while saving
  psreport -f, --format html                  Generate HTML report (default: md)
  psreport -t, --target <host/ip>             Filter attack surface to a specific host/IP
  psreport -T, --title "<title>"              Set custom report title
  psreport -p, --profile NAME                 Use a specific saved profile

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

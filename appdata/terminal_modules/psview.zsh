# PSDESC: analyze a screenshot or image with AI vision
psview() {
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]] || [[ $# -eq 0 ]]; then
        cat <<'EOF'
psview — AI-powered screenshot / image analyzer

Usage:
  psview <image>                          Analyze image with default pentest prompt
  psview <image> "<question>"             Ask a specific question about the image
  psview -p, --profile NAME <image>       Use a specific saved profile

Supported formats: PNG, JPG, JPEG, WebP, GIF

Requires a vision-capable model (Claude, GPT-4o, llava, moondream, etc.).
The analysis is saved to terminal history so psnext/psreport can use it.
EOF
        return 0
    fi

    local _base="${${(%):-%x}:A:h:h:h}"
    local _py="$_base/.venv/bin/python3"
    local _script="$_base/appdata/terminal_modules/psview.py"

    if [[ ! -x "$_py" ]]; then
        _py="python3"
    fi

    if [[ ! -f "$_script" ]]; then
        echo "psview: script not found: $_script" >&2
        return 1
    fi

    "$_py" "$_script" --base-dir "$_base" --cwd "$PWD" "$@"
}

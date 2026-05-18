psview() {
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]] || [[ $# -eq 0 ]]; then
        cat <<'EOF'
psview — AI-powered screenshot / image analyzer

Usage:
  psview <image>                      Analyze image with default pentest prompt
  psview <image> "<question>"         Ask a specific question about the image
  psview <image> --cmd                Analyze and paste best command (image only, y/n)
  psview <image> --next               Analyze and suggest next steps (full history, y/n)
  psview -m <model> <image>           Use a specific model

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

    if [[ "$*" == *"--next"* ]] || [[ "$*" == *"--cmd"* ]]; then
        # Stream analysis to terminal (via 2>/dev/tty),
        # capture best command on stdout, then ask y/n
        local _cmd
        _cmd=$("$_py" "$_script" --base-dir "$_base" --cwd "$PWD" "$@" 2>/dev/tty)
        if [[ -n "$_cmd" ]]; then
            echo -n "Paste command? [y/n] " >/dev/tty
            read -r _reply </dev/tty
            if [[ "$_reply" == [yY] ]]; then
                print -z "$_cmd"
            fi
        fi
    else
        "$_py" "$_script" --base-dir "$_base" --cwd "$PWD" "$@"
    fi
}

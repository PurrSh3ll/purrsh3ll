autoload -Uz add-zsh-hook

# Millisecond unix timestamp. Uses GNU `date +%s%3N`; falls back to
# whole-second precision (×1000) if %3N is unsupported, so the emitted value is
# always all-digits and parses cleanly on the app side.
_purrlog_now_ms() {
    local ms
    ms=$(date +%s%3N 2>/dev/null)
    if [[ "$ms" != <-> ]]; then
        ms="$(date +%s)000"
    fi
    printf '%s' "$ms"
}

_purrlog_preexec() {
    local cmd_b64 cwd_b64
    cmd_b64=$(printf '%s' "$1" | base64 -w0 2>/dev/null || printf '%s' "$1" | base64 2>/dev/null)
    cwd_b64=$(printf '%s' "$PWD" | base64 -w0 2>/dev/null || printf '%s' "$PWD" | base64 2>/dev/null)
    printf '\033]777;purrlog_cmd;%s;%s;%s\007' "$cmd_b64" "$(_purrlog_now_ms)" "$cwd_b64"
}

_purrlog_precmd() {
    local ec=$?
    printf '\033]777;purrlog_end;%d;%s\007' "$ec" "$(_purrlog_now_ms)"
}

add-zsh-hook preexec _purrlog_preexec
add-zsh-hook precmd _purrlog_precmd

autoload -Uz add-zsh-hook

_purrlog_preexec() {
    local cmd_b64
    cmd_b64=$(printf '%s' "$1" | base64 -w0 2>/dev/null || printf '%s' "$1" | base64 2>/dev/null)
    printf '\033]777;purrlog_cmd;%s;%s\007' "$cmd_b64" "$(date +%s)"
}

_purrlog_precmd() {
    local ec=$?
    printf '\033]777;purrlog_end;%d;%s\007' "$ec" "$(date +%s)"
}

add-zsh-hook preexec _purrlog_preexec
add-zsh-hook precmd _purrlog_precmd

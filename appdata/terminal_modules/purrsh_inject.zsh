# PurrSh3ll: silent variable injection via FIFO + zle -F
# PURRSH_FIFO is set per-terminal by the app to a unique FIFO path.
# When ZLE is active (user at prompt), the handler fires immediately on write.
# When a command is running, data buffers in the FIFO and fires on next prompt.
[[ -z "$PURRSH_FIFO" ]] && return
[[ ! -p "$PURRSH_FIFO" ]] && return

exec {_purrsh_inject_fd}<>"$PURRSH_FIFO"

_purrsh_inject_handler() {
    local line
    IFS= read -r -u $1 line
    [[ -n "$line" ]] && eval "$line" 2>/dev/null
    zle reset-prompt 2>/dev/null
}

zle -F $_purrsh_inject_fd _purrsh_inject_handler

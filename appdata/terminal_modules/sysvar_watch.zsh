# PurrSh3ll: auto-reload system_vars.zsh on file change (precmd hook)
_purrsh_sysvar="${${(%):-%N}:A:h}/system_vars.zsh"
_purrsh_sysvar_mtime=$(stat -c %Y "$_purrsh_sysvar" 2>/dev/null)

_purrsh_reload_sysvar() {
    local mtime
    mtime=$(stat -c %Y "$_purrsh_sysvar" 2>/dev/null)
    [[ -z "$mtime" ]] && return
    if [[ "$mtime" != "$_purrsh_sysvar_mtime" ]]; then
        _purrsh_sysvar_mtime="$mtime"
        source "$_purrsh_sysvar" 2>/dev/null
    fi
}

autoload -Uz add-zsh-hook
add-zsh-hook precmd _purrsh_reload_sysvar

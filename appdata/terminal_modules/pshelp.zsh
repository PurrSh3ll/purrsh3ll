# Store modules dir at source time when %x reliably points to this file
_PSHELP_MODULES_DIR="${${(%):-%x}:A:h}"

# Show hint before first prompt, only in first terminal per system session
autoload -Uz add-zsh-hook
_pshelp_hint_precmd() {
    add-zsh-hook -d precmd _pshelp_hint_precmd
    [[ -f /tmp/.purrsh3ll_hint_shown ]] && return
    touch /tmp/.purrsh3ll_hint_shown
    print -P "%F{240}# Type pshelp to see available tools%f"
}
add-zsh-hook precmd _pshelp_hint_precmd

# PSDESC: list all available AI tools with descriptions
pshelp() {
    local modules_dir="$_PSHELP_MODULES_DIR"

    # pshelp <command> — proxy to that command's --help
    if [[ $# -gt 0 && "$1" != "-h" && "$1" != "--help" ]]; then
        local cmd="$1"
        if typeset -f "$cmd" > /dev/null 2>&1; then
            "$cmd" --help
        else
            echo "pshelp: unknown command: $cmd" >&2
            return 1
        fi
        return 0
    fi

    # Collect PSDESC annotations from source files
    local -A _desc
    local _f _line _prev_desc _func
    setopt local_options null_glob
    for _f in "$modules_dir"/ps*.zsh; do
        [[ -f "$_f" ]] || continue
        _prev_desc=""
        while IFS= read -r _line; do
            if [[ "$_line" =~ '^# PSDESC: (.+)$' ]]; then
                _prev_desc="${match[1]}"
            elif [[ "$_line" =~ '^(ps[a-zA-Z_][a-zA-Z0-9_]*)\(\)' ]]; then
                _func="${match[1]}"
                [[ -n "$_prev_desc" ]] && _desc[$_func]="$_prev_desc"
                _prev_desc=""
            else
                _prev_desc=""
            fi
        done < "$_f"
    done

    echo ""
    echo "  \033[1mPurrSh3ll Tools\033[0m"
    echo "  ────────────────────────────────────────────────────"
    # Only show functions that have a PSDESC annotation, sorted
    local _fn _dsc
    for _fn in ${(ok)_desc}; do
        printf "  \033[36m%-16s\033[0m  %s\n" "$_fn" "${_desc[$_fn]}"
    done
    echo ""
    echo "  \033[2mpshelp <command>   show detailed help for a command\033[0m"
    echo ""
}

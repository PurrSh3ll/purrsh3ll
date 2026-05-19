# PurrShell silent terminal init
_purrsh_real="${REAL_ZDOTDIR:-$HOME}"
[[ -f "$_purrsh_real/.zshrc" ]] && ZDOTDIR="$_purrsh_real" source "$_purrsh_real/.zshrc"
unset _purrsh_real REAL_ZDOTDIR
source '/home/kali/PycharmProjects/App_beta/appdata/term_start.zsh' >/dev/null 2>&1
fc -p

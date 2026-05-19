# PurrShell silent terminal init
_purrsh_real="${REAL_ZDOTDIR:-$HOME}"
[[ -f "$_purrsh_real/.zshrc" ]] && ZDOTDIR="$_purrsh_real" source "$_purrsh_real/.zshrc"
unset _purrsh_real REAL_ZDOTDIR
source '/home/kali/PycharmProjects/App_beta/appdata/term_start.zsh' >/dev/null 2>&1
_PURRSH3LL_HINT_FLAG="/tmp/.purrsh3ll_hint_shown"
if [[ ! -f "$_PURRSH3LL_HINT_FLAG" ]]; then
  touch "$_PURRSH3LL_HINT_FLAG"
  print -P "%F{240}# Type pshelp to see available tools%f"
fi
unset _PURRSH3LL_HINT_FLAG
fc -p

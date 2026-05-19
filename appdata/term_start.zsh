THIS_FILE="${(%):-%N}"
BASE_DIR="${THIS_FILE:A:h}"


MODULES_DIR="$BASE_DIR/terminal_modules"
# load all .zsh files to current session
if [[ -d "$MODULES_DIR" ]]; then
  for f in "$MODULES_DIR"/*.zsh; do
    [[ -f "$f" ]] && source "$f"
  done
fi

# Show pshelp hint only in the first terminal opened per system session
_PURRSH3LL_HINT_FLAG="/tmp/.purrsh3ll_hint_shown"
if [[ ! -f "$_PURRSH3LL_HINT_FLAG" ]]; then
  touch "$_PURRSH3LL_HINT_FLAG"
  echo "\033[2m# Type pshelp to see available tools\033[0m"
fi
unset _PURRSH3LL_HINT_FLAG


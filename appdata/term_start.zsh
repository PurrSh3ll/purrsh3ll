THIS_FILE="${(%):-%N}"
BASE_DIR="${THIS_FILE:A:h}"


MODULES_DIR="$BASE_DIR/terminal_modules"
# load all .zsh files to current session
if [[ -d "$MODULES_DIR" ]]; then
  for f in "$MODULES_DIR"/*.zsh; do
    [[ -f "$f" ]] && source "$f"
  done
fi


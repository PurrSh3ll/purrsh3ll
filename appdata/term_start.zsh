THIS_FILE="${(%):-%N}"
BASE_DIR="${THIS_FILE:A:h}"

# App root (parent of appdata/), exported so commands and docs can reference
# app-relative paths regardless of the terminal's current directory.
export PURRSH_HOME="${BASE_DIR:h}"

MODULES_DIR="$BASE_DIR/terminal_modules"
# load all .zsh files to current session
if [[ -d "$MODULES_DIR" ]]; then
  for f in "$MODULES_DIR"/*.zsh; do
    [[ -f "$f" ]] && source "$f"
  done
fi


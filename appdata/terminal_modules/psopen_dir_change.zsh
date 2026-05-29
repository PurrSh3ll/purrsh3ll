# PSDESC: open a file or navigate to a directory in PurrSh3ll
psopen() {
  if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    cat <<'USAGE'
psopen — open a file in PurrSh3ll from the terminal

Usage:
  psopen <file> [mode]
  psopen -f <file> [-m <mode>]

Options:
  -f, --file <file>   Path to the file to open (required)
  -m, --mode <mode>   Override the open mode (default: inferred from extension)
  -h, --help          Show this help

Modes:
  py, sh, js, html, json, txt, md, ...   open in editor with syntax highlighting

Examples:
  psopen notes.md
  psopen /tmp/report.txt json
  psopen -f /tmp/exploit.py
USAGE
    return 0
  fi

  file=""
  mode=""

  # parse GNU-style options only (-f/--file and -m/--mode)
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help)
        psopen --help; return 0 ;;
      -f)
        shift
        file="$1"; shift;;
      --file)
        shift
        file="$1"; shift;;
      --file=*)
        file="${1#--file=}"; shift;;
      -m)
        shift
        mode="$1"; shift;;
      --mode)
        shift
        mode="$1"; shift;;
      --mode=*)
        mode="${1#--mode=}"; shift;;
      --)
        shift; break;;
      -* )
        printf 'psopen: unknown option: %s\n' "$1"; return 1;;
      *)
        # positional: first non-option -> file, second non-option -> mode (allowed)
        if [ -z "$file" ]; then
          file="$1"; shift
        elif [ -z "$mode" ]; then
          mode="$1"; shift
        else
          printf 'psopen: unexpected positional argument: %s (only file and mode allowed)\n' "$1"
          return 1
        fi
        ;;
    esac
  done

  if [ -z "$file" ]; then
    printf 'psopen: missing required option -f/--file — use "psopen --help" for usage\n'
    return 1
  fi

  if [ ! -e "$file" ]; then
    printf 'no such file or directory: %s\n' "$file"
    return 1
  fi

  # compute resolved absolute path (expand ~ and resolve symlinks)
  # IMPORTANT: pass "$file" as an arg to the heredoc python (args before <<)
  file_resolved=$(python3 - "$file" <<'PY'
import os,sys
f = sys.argv[1] if len(sys.argv) > 1 else ""
print(os.path.realpath(os.path.expanduser(f)) if f else "")
PY
)

  # if target is a directory — open in default file manager and exit
  if [ -d "$file_resolved" ]; then
    (xdg-open "$file_resolved" &>/dev/null &)
    return 0
  fi

  # send single OSC JSON object {file, mode}
  # Use safe python heredoc invocation so python never IndexErrors
  payload=$(python3 - "$file_resolved" "$mode" <<'PY'
import sys, json
args = sys.argv[1:]
obj = {"file": None, "mode": None}
if len(args) >= 1:
    obj["file"] = args[0]
if len(args) >= 2 and args[1] != "":
    obj["mode"] = args[1]
print(json.dumps(obj))
PY
)

  printf '\033]1337;PSOPEN=%s\007' "$payload"
}

# zsh completion: support -f/--file with file completion and -m/--mode treated as free string
_psopen_comp() {
  _arguments -C \
    '(-h --help)'{-h,--help}'[show help]' \
    '(-f --file)'-f'[file to open]:file:_files' \
    '(--file)'--file'[file to open]:file:_files' \
    '(-m --mode)'-m'[mode]' \
    '(--mode)'--mode'[mode]' \
    '1:filename:_files' \
    '2:mode:'
}
compdef _psopen_comp psopen


if [[ -n "$VIRTUAL_ENV" ]]; then
  unset VIRTUAL_ENV
  hash -r
  export PATH=$(echo "$PATH" | tr ':' '\n' | grep -v '/.venv/' | paste -sd ':' -)
fi
cd ~ || return 1
clear

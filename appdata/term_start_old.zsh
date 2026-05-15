psopen() {
  if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    cat <<'USAGE'
psopen — open a file inside PurrSh3ll

Usage: psopen -f <file> [-m <mode>]
       psopen --file <file> [--mode <mode>]
       psopen <file> [<mode>]

Options:
  -f, --file <file>     Path to file to open (required). The path must exist.
  -m, --mode <mode>     Optional mode. If omitted, infers mode from extension.
                        Available modes include:
                          • python   – open Python source file in code editor
                          • script   – open file in Python Script Runner mode
                          • txt, json, html, xml, jpg, png, ... (and others)
  -h, --help            Show this help and exit.

Examples:
  psopen Desktop/example.txt
  psopen -f /Desktop/example.txt
  psopen --file /Desktop/example.txt --mode json
  psopen Desktop/example.txt json  (The file extension can be overridden)
  psopen Desktop/test.py script (Explicitly open as Python Script Runner)

Behavior:
  - Open file '%s' in PurrSh3ll with mode '%s'.
  - The **mode** argument refers to the file's extension or a custom open mode,
    which PurrSh3ll uses to determine the appropriate opening method.
  - The opened file is held in PurrSh3ll's memory.
  - Every modification to the file automatically overwrites the original file.
  - PurrSh3ll opens files based on their extension by default, or in text mode
    if no extension is present.
  - Only the file argument is required; a single visible confirmation line is printed.
  - The script mode runs the file inside the integrated Python Script Runner.
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

  # compute resolved absolute path for printing only (expand ~ and resolve symlinks)
  # IMPORTANT: pass "$file" as an arg to the heredoc python (args before <<)
  file_resolved=$(python3 - "$file" <<'PY'
import os,sys
f = sys.argv[1] if len(sys.argv) > 1 else ""
# expand ~ and resolve symlinks; if empty, print empty string
print(os.path.realpath(os.path.expanduser(f)) if f else "")
PY
)

  # send single OSC JSON object {file, mode}
  # Use safe python heredoc invocation so python never IndexErrors
  payload=$(python3 - "$file" "$mode" <<'PY'
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

  # print confirmation using full resolved path (only change is using $file_resolved)
  if [ -n "$mode" ]; then
    printf 'PurrSh3ll opened >> %s %s\n' "$file_resolved" "$mode"
  else
    printf 'PurrSh3ll opened >> %s\n' "$file_resolved"
  fi
}

# zsh completion: support -f/--file with file completion and -m/--mode treated as free string
_psopen_comp() {
  _arguments \
    '(-h --help)'{-h,--help}'[show help]' \
    '(-f --file)'-f'[file to open]:file:_files' \
    '(--file)'--file'[file to open]:file:_files' \
    '(-m --mode)'-m'[mode]: : ' \
    '(--mode)'--mode'[mode]: : '
}
compdef _psopen_comp psopen




if [[ -n "$VIRTUAL_ENV" ]]; then
  unset VIRTUAL_ENV
  hash -r
  export PATH=$(echo "$PATH" | tr ':' '\n' | grep -v '/.venv/' | paste -sd ':' -)
fi
cd ~ || return 1
clear

# PurrSh3ll

A desktop environment for penetration testers and CTF players built on PyQt6. Combines a multi-tab terminal, script manager, file viewer, Nmap integration, and local AI assistant into a single application.

---

## Features

### Terminal
- Multi-tab terminal based on QTermWidget with Zsh shell
- Command history logged to `appdata/logs/terminal_history.jsonl` (with timestamps and exit codes)
- Per-tab zoom (Ctrl+Scroll), rename, custom environment variables
- Dynamic variable panel — track variables across sessions in real time

### Script Manager (.py files)
- GUI launcher for Python scripts with automatic help/docstring extraction
- Dependency detection — missing packages can be installed directly from the UI
- Per-script: execution history, notes, favorites, documentation cache
- Virtual environment detection and selection

### Nmap Integration (.psnmap files)
- Save and reuse Nmap scan profiles (name, command, description)
- Full execution history with timestamps
- **WebMap** — interactive Nmap result visualization via Docker (`reborntc/webmap`)

### File Viewer
- Syntax highlighting for 40+ file types: Python, Bash, PowerShell, C/C++, Java, JavaScript, Go, Lua, Perl, Ruby, PHP, C#, SQL, HTML, JSON, YAML, Markdown and more
- Chunked loading for large files
- In-file search with regex support and multi-flag filtering

### Module Tree
Built-in modules organized into categories:

| Category | Contents |
|---|---|
| **RedTeam** | StealthKit, WiFury, ReconShadow, HumanVector, ScanForge, ExploitForge, HashRipper, PostIntruder, PersistenceKit, TrackCleaner, ZombiCore, PentestReport |
| **BlueTeam** | Defense tools |
| **Forensic** | Digital forensics |
| **BrainDump** | Notes and references |
| **Cyb3rBreak** | CTF challenges |
| **Cyb3rCollector** | Listeners, stagers, WebMap |
| **MissionCenter** | Operation management |

User modules go in `usermodules/` and appear in the tree automatically.

### AI / Chat Panel
Local LLM integration without sending data to external services:

- **llama.cpp CLI** — run GGUF models directly
- **llama.cpp Web UI** — browser-based interface via local server
- **CLI Custom** — any CLI tool (e.g. `ollama run model`)
- **Web UI Custom** — any Docker-based web UI

### Panels
- **Slide panel** — observable variables, updates in real time
- **Mode panel** — terminal profiles and environment presets
- **Notes panel** — persistent side notes (auto-saved)
- **Chat panel** — AI assistant

### Themes
Multiple built-in color themes switchable from the menu. Theme is applied instantly, terminals update in the background.

---

## Requirements

### System
- Linux (tested on Kali Linux)
- Zsh (`/bin/zsh`)
- Docker — required for WebMap and llama.cpp Web UI
- `sudo` access — required for Docker container management
- System keyring (for secure password storage)

### Python
- Python 3.10+
- PyQt6
- QTermWidget (`qtpyterminal`)
- `watchdog`
- `pyfiglet`
- `keyring`

Install dependencies:
```bash
pip install -r requirements.txt
```

### Optional
- `llama-cli` / `llama-server` — for local LLM inference
- `ollama` — alternative LLM backend
- Docker image `reborntc/webmap` — for Nmap visualization

---

## Installation

```bash
git clone <repo>
cd App_beta
pip install -r requirements.txt
python main.py
```

To start with debug logging to stderr:
```bash
python main.py --debug
```

---

## Configuration

Main config file: `appdata/app_config.json`

| Key | Description |
|---|---|
| `window.resolution` | Window size `[width, height]` |
| `window.start_screen` | Window position `[x, y]` |
| `performance.lightweight_web_browser` | Use lightweight rendering |
| `behavior.delete_logs_at_close` | Clear terminal history on exit |
| `behavior.delete_notes_at_close` | Clear notes on exit |
| `behavior.save_sys_vars_at_close` | Persist system variables |
| `llama.llm_cli_path` | Path to `llama-cli` binary |

---

## Data Layout

```
appdata/
├── app_config.json          # Main configuration
├── themes.json              # Theme definitions
├── dynamic_variables.json   # User-defined variables
├── psnotes.txt              # Side notes
├── ob_panel_state.json      # Observable panel state
├── logs/
│   ├── app.log              # Application log (rotated, max 2MB × 3)
│   └── terminal_history.jsonl  # Terminal command history
├── scripts_help/            # Extracted --help output cache
├── scripts_docs/            # Docstring cache
├── scripts_history/         # Per-script execution history
├── scripts_favorities/      # Favorite commands
├── scripts_notes/           # Per-script notes
├── terminal_modules/        # Zsh environment setup
│   └── system_vars.zsh
└── agent_modes/             # Claude agent configurations

appmodules/                  # Built-in modules (read-only)
usermodules/                 # User modules
icons/                       # Application icons
```

---

## Logs

Application logs are written to `appdata/logs/app.log` with rotation (2 MB per file, 3 backups).

Log levels:
- `DEBUG` — verbose, file only
- `WARNING` / `ERROR` — file + stderr (always visible in terminal)

Run with `--debug` to show DEBUG level in stderr as well.

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+Scroll` | Zoom in/out in terminal or file viewer |
| `Enter` on tree item | Open file or expand/collapse folder |
| Double-click tree item | Open file in new tab |

---

## Notes

- WebMap Docker container (`webmap`) is automatically removed on application exit if it was started during the session.
- Terminal history is deleted on exit by default (configurable in settings).
- Theme changes are limited to sessions with fewer than 30 open tabs to maintain performance.

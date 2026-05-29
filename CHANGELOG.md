# Changelog

All notable changes to PurrSh3ll are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Fixed

- **Markdown preview**: zoom (buttons + Ctrl+Scroll) now scales images alongside text; images fit the preview width automatically and never upscale beyond natural size
- **Markdown preview**: content no longer cut off on file open without requiring a splitter resize; horizontal scrollbar removed to prevent flicker
- **Terminal**: split view labels corrected — "Split View Left-Right" and "Split View Top-Bottom"
- **Terminal**: zoom (buttons, Ctrl+Scroll, right-click menu) now works correctly in split terminals, including Zoom Reset option
- **Terminal**: commands executed in split terminals are now logged to `terminal_history.jsonl` (visible to `psfix`, `psnext`, `psreport`)
- **Terminal**: Pause Agent Monitoring now also pauses history logging for the split terminal in the same tab
- **Terminal**: `psopen` now opens files from split terminals the same way as the primary terminal
- **Terminal**: split terminal now receives silent variable/alias injection from Observable Panel (own FIFO assigned at creation, cleaned up on unsplit)

---

## [1.0.0] — 2026-05-27 — Early Access

### Added

#### AI Tools (ps* commands)
- `psask` — ask the active AI profile a direct question (supports `--rag` flag)
- `pschat` — persistent chat session with conversation history (supports `--rag`, `--clear`)
- `pscmd` — generate a shell command from a natural language description
- `psfix` — explain and fix the last terminal error; Fix mode pastes corrected command at prompt
- `psnext` — suggest next pentest steps based on terminal history; asks y/n to paste best command
- `psreport` — generate a structured Markdown/HTML pentest report from terminal history (`--deep`, `--verbose`, `--format html`)
- `pstldr` — TL;DR summarizer for last command output, files, or piped input (`--tail`, binary detection)
- `psrag` — query the local RAG knowledge base (`-n`, `--show-sources`, `-m`)
- `psview` — analyze a screenshot or image with a vision-capable AI model (`--next`, `--cmd`)
- `pshelp` — list all available ps* tools with auto-discovery
- All ps* tools support `-m MODEL` flag to override the active model per invocation
- All ps* tools respect per-profile `context_tokens` limit instead of hardcoded values

#### Terminal
- Multi-tab Zsh terminal with per-tab renaming, zoom, and custom environment variables
- Full session recording to `appdata/logs/terminal_history.jsonl` (commands, output, timestamps, exit codes)
- Error overlay with **Explain**, **Fix**, and **Analyze** buttons on failed commands
- Analyze button shows y/n prompt to paste corrected command after deep analysis
- `pshelp` hint overlay on first terminal tab (disappears on keypress)

#### Voice Interface
- Wake word detection ("Hey Jarvis") via OpenWakeWord
- Speech-to-text transcription via Faster-Whisper (tiny, CPU int8)
- Voice confirmation loop — say "accept" or "cancel" after command is generated
- Voice command button in the toolbar
- Queue-based audio buffering optimized for virtual machines

#### RAG Knowledge Base
- ChromaDB + sentence-transformers (multilingual MiniLM) — fully offline
- File watcher via watchdog — auto-indexes changes in BrainDump folder
- Switchable knowledge bases and embedding models from AI Settings

#### Chat Panel
- Three modes: `run + cli`, `run + web`, `connect`
- Docker container management for Open WebUI from within the app
- Ollama profile names loaded in chat combo; run command built from profile
- Blinking info button when Open WebUI container is not yet reachable
- Model combobox hidden in web/connect modes

#### AI Settings
- 7 supported providers: Ollama, OpenAI, Anthropic, Groq, Gemini, OpenRouter, HuggingFace
- Per-profile Behavior settings: disable thinking, fast answers, custom parameters
- API keys stored securely in system keyring with file fallback
- Autofill API key in Add Profile dialog from existing same-provider profile
- Confirmation dialog before removing a provider profile
- Floating Active Profile combobox in the bottom-right corner

#### Markdown File Viewer
- Split view: editor on the left, rendered preview on the right
- Zoom in/out buttons — synchronize text size across editor and preview
- Image scaling in preview — images resize proportionally with zoom level
  (natural sizes cached; applied via `QTextImageFormat` after each render)
- Action links in Markdown — click to run terminal commands or switch themes

#### Welcome Screen
- Hacker quote rotation every 10 seconds
- Double-click to customize text, image, or background
- Default animated GIF background

#### Other Panels
- Notes — persistent side notes, auto-saved, Markdown rendering with action links
- Snippets — reusable code/command snippets
- Observable Variables — real-time display of tracked shell variables
- Mode Profiles — terminal environment presets for different tasks
- Script Manager — run Python scripts with auto-extracted help/docstrings, dependency detection
- File Viewer — syntax highlighting for 40+ file types, chunked loading, regex search
- Nmap Integration — scan profiles (`.psnmap`), full scan history, WebMap via Docker

#### Themes & Customization
- Large collection of built-in color themes (Legacy Hacker, Cyberpunk, Red Team, Default, and more)
- Full visual customization: colors, fonts, layout

#### Installation
- `install.sh` — lite installer (core app + QTermWidget, optional `--voice`)
- `install_full.sh` — full installer (Ollama, aichat, Docker, Open WebUI, WebMap, AI Skills)
- Correct Docker installation on Kali Linux (`docker.io`, `docker-cli`, `containerd` from apt)
- Animated spinner for long-running steps (Ollama install, Docker image pulls)
- AI Skills as git submodules: `awesome-claude-skills-security`, `claude-code-pentest`

#### Help Menu
- Author dialog with GitHub, LinkedIn, Email, and YouTube links
- What's New and Check for Updates entries (coming soon popup)
- Licenses dialog listing all open-source dependencies

### Fixed

- Hardcoded `/home/kali` path in `.zshrc` replaced with dynamic resolution (`${${(%):-%x}:A:h:h}`)
- Window title shows "Early Access" instead of "CTF mode"
- Docker `command not found` after install on Kali — added `docker-cli` and `systemctl enable docker --now`
- Ollama installation flooding terminal output — wrapped in background spinner
- Docker pull output suppressed with `--quiet`
- Active profile combobox no longer covers side panels
- HuggingFace provider switched to featherless-ai router
- `psask` exits with a clear error message when no active API profile is set
- Thinking/reasoning parameters sent only to models that support them
- `psfix` Fix mode pastes silently without echoing `psfix` to the terminal
- Voice mode green state bug after cancel/accept
- Welcome image scales correctly with window and splitter resizes
- Right viewport margin added to notes editor for easier panel resize

### Changed

- Removed unused llama config fields from `app_config.json` (`llama_cli_path`, `llama_server_path`, `mmproj_file`, `model_path`, `cli_custom_cmd`, `webui_custom_cmd`, `ollama_model`, `ollama_disable_thinking`, `ollama_fast_answers`)
- Runtime files `session.json` and `ob_panel_state.json` removed from git tracking
- `psask` renamed to `psrag` for RAG queries; unified AI assistant added as `psai.py`

---

## Notes

- Ollama LLM models are not bundled — each model is downloaded separately on demand (2–8 GB per model)
- Full installation (`install_full.sh`) may take 10–20 minutes depending on internet speed
- Voice support requires optional packages (`--voice` flag during installation)
- Python venv is approximately 1.4–1.5 GB (dominated by PyQt6 + onnxruntime)

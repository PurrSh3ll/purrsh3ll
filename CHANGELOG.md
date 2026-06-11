# Changelog

All notable changes to PurrSh3ll are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added

- **Installer**: Ollama install retries up to 3 times on transient HTTP errors (504, 503, 502)
- **Installer**: timer loop shows download percentage during Ollama install (`downloading: 42.3% (30s elapsed)`)
- **Installer**: Docker image pulls show layer progress with total count (`8/47 layers done`) and download bytes per active layer
- **Installer**: `sudo -v` refresh before each Docker image pull to prevent sudo password prompt mid-output
- **Installer**: apt progress now visible during system dependencies install (`Get:`, `Unpacking`, `Setting up`)
- **Installer**: pip package names visible during Python packages install (`Collecting`, `Downloading`, `Successfully installed`)
- **Installer**: `docker-cli` added to apt install — provides `/usr/bin/docker` binary on Kali (previously only daemon was installed)
- **Installer**: `DOCKER_OK` now set when Docker is already installed on re-run
- **Installer**: `dpkg -s docker.io` used as fallback check when `command -v docker` misses freshly installed binary
- **Installer**: interactive whiptail checklist installer replacing `install.sh` and `install_full.sh` — optional components selectable per run (Ollama, aichat, Docker, Open WebUI, WebMap, Voice, AI Skills, embedding model)
- **Installer**: optional multilingual embedding model download (`paraphrase-multilingual-MiniLM-L12-v2`, ~220 MB) selectable during install; downloaded once and reused on every RAG use
- **Settings → Agent run command**: pre-filled with `claude --dangerously-skip-permissions` after fresh install
- **README**: Requirements section simplified — only OS, Python and microphone listed; all other dependencies noted as installed by `install.sh`
- **README**: RAM usage table extended with RAG reranking model (`+100–400 MB during reranking`) and Voice (`+300–600 MB during recognition`) rows
- **Active AI profile combo**: tooltip on hover shows provider and model of the selected profile
- **Active AI profile combo**: per-item tooltip in dropdown shows provider and model for each profile
- **ps* tools**: all CLI tools (`pscmd`, `psfix`, `psnext`, `psreport`, `pstldr`, `psview`) now show `Querying {model} via {provider}…` before each request, consistent with `psask`/`pschat`
- **ps* tools**: `-m` flag now accepts a saved **profile name** instead of a raw model name — switches the full profile (provider, URL, API key, model); unknown name shows a concise error pointing to AI Settings
- **ps* tools**: help text in all zsh wrappers updated — `-m <model>` → `-m <profile>` across all tools; `psnext.zsh` extended with `--rag` and `-n` options
- **psnext**: `--rag` flag enriches next-step suggestions with knowledge base context; `-n N` controls chunk count (default 5); RAG query derived from `--target` or last history command
- **psask / pschat**: `--rag` now respects the re-ranking setting from AI Settings — fetches a candidate pool (`max(20, n)`), applies cross-encoder re-ranker, then trims to `-n` best chunks
- **AI Settings → AI/LLM**: new checkbox "Clear pschat history on exit" — when enabled, all `appdata/chat_sessions/*.json` files are deleted on application close; default on
- **Behavior dialog — Context limit**: added "Default" reset button next to the spinbox — resets value to 0 (provider default) in one click
- **Behavior dialog — Context limit**: added ⓘ info button with tooltip and clickable dialog explaining the context limit field
- **Behavior dialog — Context limit**: auto-detects context window size for the active Ollama model via `/api/show` endpoint — displayed as `default (131 072)` in the spinbox special-value text; uses a thread-safe `pyqtSignal` relay so the UI update always runs on the main thread
- **Chat Panel — CLI mode**: `OLLAMA_NUM_CTX=<value>` env var prefix added to the `ollama run` command when `context_tokens` is set in the active profile
- **Chat Panel — CLI mode**: `--system "Answer as briefly as possible…"` flag added to the `ollama run` command when Fast answers is enabled
- **pschat**: `num_ctx` option passed to Ollama API when `context_tokens` is set in the active profile
- **psask / chat**: Fast answers — appends brevity instruction to query (ask) or prepends system message (chat) when "Fast answers" is checked and no custom params are set
- **psai**: thinking process now displayed with dim ANSI style (`\033[2m💭 …\033[0m`) when model emits reasoning tokens; resets cleanly when content begins
- **Themes**: added Sakura Protocol, Tropical Brazil, MS-DOS and Pierogi Overflow theme
- **File viewer**: CSV and TSV files displayed as interactive sortable tables
- **File viewer**: PDF files rendered with page navigation
- **RAG**: PDF files now indexed and searchable in the knowledge base
- **File viewer**: audio and video files playable directly in the app
- **AI Settings → RAG tab**: reorganized into four named sections — Knowledge, Embedding, Re-ranking, Downloaded models
- **AI Settings → RAG tab**: ℹ info button in Embedding and Re-ranking sections — click opens popup with guidance on model selection, language support, and RAM usage; hover shows a short warning tooltip
- **AI Settings → RAG tab**: tooltips on individual embedding and reranker combo items — describe supported languages, model size, and use case
- **AI Settings → RAG tab**: double-click on a model in Downloaded models list shows its info popup
- **AI Settings → RAG tab**: Indexed files list capped at 6 visible rows with scrollbar
- **AI profiles**: API provider profiles moved to a separate `appdata/api_profiles.json` file — gitignored; application creates an empty file on first launch if missing
- **BrainDump**: `purrsh3ll_app_guide.md` added — comprehensive in-app guide optimized for RAG retrieval covering all features, CLI tools with flags and examples, FAQ and troubleshooting
- **Model context window registry**: `appdata/model_ctx_registry.json` — 379+ models across 9 providers (OpenAI, Anthropic, Groq, OpenRouter, Gemini, Mistral, Together AI, HuggingFace, Ollama); used to display read-only context window info in each profile's Behavior dialog
- **Behavior dialog**: read-only "Context window" label — shows the model's max input tokens from the registry; lookup handles `models/` prefix (Gemini) and `:variant` suffixes (OpenRouter); unknown models show `unknown model — safe default: 32 768 tokens`
- **Behavior dialog**: editable context window override — spinbox + logarithmic slider (512–2 000 000 tokens), hidden under "Override context window for prompt compensation" checkbox; value saved per-profile as `context_tokens`; "Default" button resets to registry value
- **Token label**: prompt token count displayed in bottom-left corner after each `psai`/`psrag` call — shows a 10-step progress bar and fill percentage (e.g. `▓▒░░░░░░░░ 12%`); reverts to `PurrSh3ll` after 10 seconds
- **Token label**: `⛔ CTX_OVER ▓▓▓▓▓▓▓▓▓▓ 134%` shown when prompt exceeds context window — label turns red using `button_info_hover` theme color; restores normal color on hide
- **Token label**: PIL-based image token estimation for multimodal messages — uses OpenAI tile formula `ceil(w/512)*ceil(h/512)*170+85`; falls back to 512-token flat estimate if Pillow unavailable
- **psai**: inference stats line printed after each response — `↑1587 ↓408 tok  ·  12.4 tok/s  ·  34.1s`; input tokens shown when available (Ollama, Anthropic, OpenAI-compat with `stream_options`)
- **psai**: OpenRouter input token count now captured from usage field in last streaming chunk — fixes missing `↑` arrow in stats line
- **AI Settings → ps* tools**: three new checkboxes — "Show inference stats after response" (`psai_show_stats`), "Show 'Querying model…' info line" (`psai_show_querying`), "Auto-open psfix on command error" (`psfix_auto_open`); all enabled by default
- **pstldr**: PDF files now supported — text extracted via PyMuPDF (`fitz`) with automatic fallback to `pypdf`; all pages sent to the model without truncation
- **psrag**: `_build_prompt(query, chunks)` now called before `_run_llm` — fixes `UnboundLocalError` on every query
- **psview**: multimodal messages normalized to Ollama native format before sending — extracts base64 images into `images` array and joins text parts into plain string; fixes HTTP 400 on Ollama vision models
- **Installer**: `OLLAMA_OK` and `AICHAT_OK` flags set when tools already installed — fixes summary showing `✗ failed` for pre-installed components
- **Installer**: Open WebUI and WebMap Docker images skipped if already present locally (`docker image inspect`) — avoids re-pull on every re-run
- **Installer**: Docker presence detected independently of checklist selection — Open WebUI/WebMap pulls now work when Docker is pre-installed but not selected
- **Installer**: embedding model download skipped if `.onnx` files already present in cache directory
- **Installer**: `git pull --ff-only` failure is non-fatal — shows warning and continues instead of aborting
- **Installer**: incomplete QTermWidget wheel cache removed automatically (< 100 KB) and re-downloaded
- **Installer**: aichat install wrapped in error handling — shows `warn` on failure instead of crashing with `set -e`

### Removed

- **tiktoken**: removed from About/licenses dialog and uninstalled from venv — no longer used anywhere in the project
- **Behavior dialog — Context limit**: spinbox, reset button, info button and Ollama auto-detect thread removed — context limit is now read-only info derived from the model registry
- **ps* tools**: tiktoken dependency and token-based history trimming removed from `psai`, `psfix`, `psnext`, `psview`, `psrag_query` — history loading replaced with last-40-entries count-based approach
- **psreport**: map-reduce chunking in deep mode removed — all entries sent in a single request
- **pstldr**: `--tail` flag removed — file content sent to the model in full without truncation

### Fixed

- **Session restore**: files now reopen with the correct loader — `.purr` files (psnmap, psc2) and all other typed loaders restore using the saved `class_name` instead of falling back to `Text_file`; `session.json` format updated to `[{path, class_name, icon_token}]` with full backwards-compatibility for old plain-string entries
- **Session restore**: tab icons now restored correctly — `icon_token` saved per-tab and reused on restore; previously all restored tabs showed the default file icon regardless of extension
- **Script loader (.py)**: docs and help tabs now auto-refresh when the file is modified on disk — `QFileSystemWatcher` monitors the open file and calls `update_docs()` / `update_help()` automatically; handles atomic-save editors (PyCharm, VS Code) by re-adding the path to the watcher after each rename-based save
- **Behavior dialog**: clicking a checkbox (Disable thinking, Hide thinking, Fast answers) while Custom parameters is checked now checks the clicked option and automatically unchecks Custom parameters; previously those checkboxes were disabled and could not be interacted with
- **Behavior dialog**: Custom parameters text field resizes with the dialog window — replaced `setFixedHeight` with `setMinimumHeight` and added `stretch=1`; dialog now has a visible resize grip
- **Behavior dialog**: scrollbar click inside the Custom parameters field no longer clears the placeholder text — replaced `QTextEdit` + manual `focusInEvent`/`focusOutEvent` with `QPlainTextEdit` and native `setPlaceholderText()`
- **AI Settings → RAG tab**: Rerank model combobox scrollbar color now matches the active theme — converted to `_ScrollableComboBox` with themed scrollbar stylesheet; both RAG comboboxes now update their scrollbar style on every theme change
- **psnmap**: added tooltips to the options button (⚙ `Configure scan profiles and psnmap options`) and the WebMap button (🌐 `Start WebMap container`)
- **psai**: thinking text color changed from dim (`\033[2m`) to gray (`\033[90m`) — consistent with info lines; animated braille spinner shown while thinking is hidden
- **psai**: Hide thinking — display-only suppression replacing the unreliable API-level `disable_thinking` for non-Ollama providers; Ollama retains both checkboxes (Disable thinking + Hide thinking output)
- **Terminal**: `Ctrl+Shift+V` (paste) no longer crashes the application when focus is in a file editor window — `TypeError` from `QScrollArea.parent()` traversal now caught and handled gracefully
- **Installer**: duplicate info line before embedding model spinner removed
- **Installer**: Ollama size corrected to `~1.5 GB`, Open WebUI to `~4.8 GB`, WebMap to `~1.5 GB`
- **Themes**: default theme reset to `default` — was incorrectly committed as `Red Team`
- **Ollama**: `"think"` field no longer sent when `disable_thinking` is off — omitting it lets thinking-capable models use their default behavior, and prevents HTTP 400 errors on models that don't support thinking
- **psopen**: files now open in the correct viewer based on extension (`.md` → Markdown, `.html` → HTML, `.pdf` → PDF viewer, audio/video → media player) — previously all files landed in the unsupported-file fallback due to `mode=null` overriding the `"Default"` parameter; `.py` opens as code viewer (`Python_file`), `.purr` opens as plain text
- **psfix**: system info (`System: Linux …`) added to `--explain` and default fix mode prompts — was only present in `--analyze` mode
- **psai ask / chat**: `KeyboardInterrupt` (Ctrl+C) now exits cleanly with code 130 and resets ANSI dim style if interrupted during thinking output — no traceback printed; all three streaming paths covered (`_stream_ollama_native`, `_stream_openai_compat`, `_stream_anthropic`) plus top-level `main()` handler
- **psai ask / chat**: thinking process was always disabled — `think` flag must be at the **top level** of the request body, not inside `options`; fixed for Ollama native endpoint
- **psai ask / chat**: `disable_thinking` in Behavior now correctly suppresses thinking output — switched Ollama calls to native `/api/chat` endpoint (`_stream_ollama_native`) which correctly honors `think: false`; `/v1/chat/completions` ignored the flag for this model family
- **psai chat**: `delta.get("reasoning")` used instead of `delta.get("thinking")` — Ollama's OpenAI-compat stream uses field name `"reasoning"` for thinking tokens
- **Behavior dialog — Context limit**: spinbox stepped from 0 instead of the default value (16 000) — fixed by subclassing `QSpinBox` and overriding `stepBy()` to start from `_ctx_default`
- **Behavior dialog — Context limit**: context window number displayed as `131,072` — now formatted with space separator: `131 072`
- **Welcome screen dialog**: colors did not match current theme — fixed by applying `c.dialog_stylesheet` instead of `c.messagebox_stylesheet`
- **Terminal right-click context menu**: colors did not match current theme — `menu.setStyleSheet(menu_stylesheet)` applied to all three QMenu instances (main terminal, split terminal, tab bar) and their `_scheme_menu` submenus
- **Observable Panel**: "Missing Data" warning dialog text color did not match theme — `c.messagebox_stylesheet` now applied before `msg.exec()`
- **Syntax highlighting**: all 19 hand-written regex highlighters replaced by a single `PygmentsHighlighter` backed by the Pygments library — 500+ languages supported, edge-cases handled by the community, colors still driven by `qss_QPainter` theme
- **Syntax highlighting**: files with unknown extensions (`.yaml`, `.toml`, `.css`, `.rs`, `.ts`, `.env`, `Dockerfile`, `Makefile` etc.) now auto-detect language via `guess_lexer_for_filename()` and receive syntax highlighting automatically
- **File icons**: unknown extensions now show a neutral icon instead of "unsupported"; the unsupported icon is reserved for 62 known binary/non-openable formats (video, audio, archives, executables, fonts, 3D assets etc.)
- **HTML viewer**: three view mode buttons (`</>` code, `◫` split, `≡` preview) added before the browser button — split view is the default
- **testfolder**: removed `usermodules/testfolder/` from git tracking — folder is now ignored via `.gitignore` and will no longer appear in the repository; files remain locally
- **Security**: sudo password no longer stored in GNOME Keyring — now kept in a `bytearray` in RAM for the session duration and securely zeroed at shutdown via `ctypes.memset`; eliminates "Unlock Login Keyring" popup on application exit
- **Markdown preview**: zoom (buttons + Ctrl+Scroll) now scales images alongside text; images fit the preview width automatically and never upscale beyond natural size
- **Markdown preview**: content no longer cut off on file open without requiring a splitter resize; horizontal scrollbar removed to prevent flicker
- **Terminal**: split view labels corrected — "Split View Left-Right" and "Split View Top-Bottom"
- **Terminal**: zoom (buttons, Ctrl+Scroll, right-click menu) now works correctly in split terminals, including Zoom Reset option
- **Terminal**: commands executed in split terminals are now logged to `terminal_history.jsonl` (visible to `psfix`, `psnext`, `psreport`)
- **Terminal**: Pause Agent Monitoring now also pauses history logging for the split terminal in the same tab
- **Terminal**: `psopen` now opens files from split terminals the same way as the primary terminal
- **Terminal**: split terminal now receives silent variable/alias injection from Observable Panel (own FIFO assigned at creation, cleaned up on unsplit)
- **Terminal**: split terminal right-click menu now includes Find option with theme-aware search bar styling
- **Terminal**: reduced visual artifacts after search bar toggle and split/unsplit — improved repaint logic using `setTerminalFont` to trigger full character grid recalculation (known issue: artifacts may still appear in some cases)
- **psopen**: rewrote file opening to use OSC escape sequence protocol — fixes paths with spaces, eliminates race conditions between terminals
- **psopen**: directories now open silently in the default file manager (`xdg-open`)
- **psopen**: removed `PurrSh3ll opened >>` confirmation text from terminal output
- **Snippets**: placeholder dialog is now non-modal — other windows (terminal, tabs) remain accessible while filling in values; all placeholders shown at once in a single form
- **psview**: always showed 1 token regardless of image size — `len()` on multimodal content list returned list length instead of character count; fixed by `_estimate_prompt_tokens()` with PIL-based image size detection
- **psrag**: `UnboundLocalError: cannot access local variable 'prompt'` on every query — `_build_prompt()` was defined but never called in `main()`
- **psview + Ollama**: HTTP 400 `cannot unmarshal array into Go struct field ChatRequest.messages.content of type string` — Ollama native `/api/chat` requires `content` as string + `images` as separate list; fixed by normalizing messages in `_stream_ollama_native`
- **QFileSystemWatcher / token label**: `QFileSystemWatcher` and `QTimer` were created in `Controller.__init__` before `QApplication` existed (module-level import ordering) — inotify registration failed silently; moved to `setup_psai_tok_watcher()` called via `QTimer.singleShot(0, ...)` in `_install_filters()`

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



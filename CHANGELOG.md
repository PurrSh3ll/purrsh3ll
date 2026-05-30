# Changelog

All notable changes to PurrSh3ll are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added

- **PDF file viewer**: PDF files now open in a dedicated in-app viewer with page navigation (◀ ▶), zoom controls (buttons + Ctrl+Scroll, range 25%–400%), and an "ℹ Info" button that opens a separate window with six sections — File Info (PDF version, page count, encryption status, permission flags, PyMuPDF metadata: title/author/subject/keywords/creator/producer/dates), Metadata exiftool (async), Structure (table of contents up to 10 entries, annotations by type, form widget count, embedded files with sizes), Embedded URLs (all hyperlinks extracted per page), IoC Scan (xref-level scan for `/JS`, `/JavaScript`, `/OpenAction`, `/AA`, `/Launch`, `/SubmitForm`, `/GoToR`, `/GoToE`, `/RichMedia`, `/XFA` — grouped by key with xref numbers), Integrity (MD5 + SHA256 with copy buttons, async); "↗ Open in system viewer" button in title bar; powered by `PyMuPDF` (`fitz`) and `exiftool`; graceful fallback message if PyMuPDF is not installed
- **Video file viewer**: video files (mp4, mkv, mov, avi, wmv, flv, webm, m4v, 3gp, ogv, mpeg4) now open in a dedicated in-app viewer with playback controls (play/pause/stop, seek bar, volume) and an "ℹ Info" button that opens a separate window with: file info (duration, resolution, FPS, codec, bitrate, size, permissions), metadata panel powered by `exiftool` (GPS coordinates marked with 📍, encoder, creation date, device make/model, all OSINT-relevant fields shown first), and an integrity section with MD5 + SHA256 hashes (copyable) plus a size/duration anomaly check; "↗ Open in system player" button opens the file in the default system player; powered by `QMediaPlayer` + `QVideoWidget` (PyQt6 QtMultimedia) and `exiftool`
- **Audio file viewer**: audio files (mp3, flac, ogg, wav, aac, wma, opus, aiff, aif, aifc, oga, mp2) now open in a dedicated viewer with a full playback player (play/pause/stop, seek bar, volume), an "ℹ Info" button that opens a separate window with five sections — File Info (mutagen: duration, bitrate, sample rate, channels, format, permissions; exiftool technical fields: ChannelMode, BitrateMode, LameVersion, LameEncoderSettings, VBR info, ReplayGain, VendorString, BWF broadcast fields), Raw Frames (ID3 version/size/padding, APIC cover art with size, PRIV private frames with owner identifier, GEOB embedded objects, TXXX custom fields, UFID MusicBrainz identifiers, URL frames, ID3v2 date frames, FLAC audio MD5 signature, OGG/FLAC vendor string), Metadata Tags (all ID3/Vorbis/MP4 tags in OSINT priority order), Metadata exiftool (LAME encoder settings, VBR method/quality, ChannelMode, BWF originator/UMID/CodingHistory for broadcast WAV, CreateDate, MIMEType), Integrity (MD5 + SHA256 hashes with copy buttons, size/duration anomaly check, steganography indicators: large ID3 header, unusual padding, multiple/oversized APIC frames, GEOB presence, large PRIV payload, FLAC MD5=0); "↗ Open in system player" button in title bar; powered by `pygame` (playback), `mutagen` (metadata) and `exiftool`
- **Syntax highlighting**: all 19 hand-written regex highlighters replaced by a single `PygmentsHighlighter` backed by the Pygments library — 500+ languages supported, edge-cases handled by the community, colors still driven by `qss_QPainter` theme
- **Syntax highlighting**: files with unknown extensions (`.yaml`, `.toml`, `.css`, `.rs`, `.ts`, `.env`, `Dockerfile`, `Makefile` etc.) now auto-detect language via `guess_lexer_for_filename()` and receive syntax highlighting automatically
- **File icons**: unknown extensions now show a neutral icon instead of "unsupported"; the unsupported icon is reserved for 62 known binary/non-openable formats (video, audio, archives, executables, fonts, 3D assets etc.)
- **HTML viewer**: three view mode buttons (`</>` code, `◫` split, `≡` preview) added before the browser button — split view is the default

### Fixed

- **testfolder**: removed `usermodules/testfolder/` from git tracking — folder is now ignored via `.gitignore` and will no longer appear in the repository; files remain locally
- **PDF file viewer**: `Pdf_file` is a plain Python class (not a `QObject` subclass) — `installEventFilter(self)` raised `TypeError`; replaced with a dedicated `_CtrlScrollFilter(QObject)` helper that holds the zoom callbacks and is installed on the scroll area viewport
- **Audio/Video file viewer**: opening a tab no longer shifts the file tree splitter — tab page now returns `QSize(0, 0)` from `sizeHint()` and `minimumSizeHint()` so Qt treats it as having no preferred size; filename in the tab label clips gracefully and reveals itself as the splitter is widened
- **Audio file viewer**: pygame startup banner no longer printed to terminal on every application launch — suppressed via `PYGAME_HIDE_SUPPORT_PROMPT=1`
- **Audio file viewer**: integrity hashes (MD5/SHA256) were permanently stuck on "computing..." — `QTimer.singleShot` called from a `threading.Thread` has no Qt event loop so the callback never fired; replaced with a shared-dict result and a polling `QTimer` in the main thread
- **Audio file viewer**: duration showed `/ 0:00` for WAV files without ID3 tags — mutagen objects are falsy when tagless (`bool(audio) == False`) so the `if audio and audio.info` check silently skipped them; changed to `is not None`
- **Audio file viewer**: size/duration anomaly check triggered on every file — mutagen returns `info.bitrate` in bps (e.g. 320000) while `actual_kbps` was computed in kbps (~320), giving ratio ≈ 0.001; fixed by converting to kbps (`// 1000`) at storage time
- **Audio file viewer**: playback buttons disabled on file open — `SDL_AUDIODRIVER` set at module import time failed inside the Qt app context; replaced with a driver fallback chain tried at init time: `pipewire → pulseaudio → SDL auto-detect`
- **Audio file viewer**: in-app audio stuttering — switched SDL to native PipeWire driver (SDL 2.28+) and aligned mixer buffer to `max-quantum = 8192` from the PipeWire VM fix config
- **Terminal**: `pshelp` hint no longer printed in the terminal on startup — only the overlay widget remains
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

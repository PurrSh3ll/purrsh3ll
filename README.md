# PurrSh3ll

**AI-powered terminal environment for penetration testers, CTF players, and security learners.**

PurrSh3ll is a desktop application built on Kali Linux that brings together a multi-tab terminal, local AI assistant, RAG knowledge base, voice interface, and a suite of AI-powered CLI tools — all in one place, fully offline.

<img src="docs/images/app_image1.png" width="900"/>

## Demo

[![PurrSh3ll — 6-Minute Feature Demo](https://img.youtube.com/vi/kpUUVxBdFqE/maxresdefault.jpg)](https://www.youtube.com/watch?v=kpUUVxBdFqE)

https://www.youtube.com/watch?v=kpUUVxBdFqE

---

## Why PurrSh3ll?

Security professionals juggle dozens of tools, notes, and context across long engagements. PurrSh3ll keeps everything in one window and makes AI assistance available without sending sensitive data to the cloud.

- **Local-first** — your data never leaves the machine
- **Context-aware AI** — the assistant knows your terminal history and your notes
- **Built for the terminal** — not a browser, not an IDE, not a chat app

---

## Features

### Terminal
- Multi-tab Zsh terminal with per-tab renaming, zoom, and custom environment variables
- Full command history logged to JSONL with timestamps and exit codes
- Error overlay with AI-powered Explain / Fix / Analyze on failed commands

### AI Assistant (CLI)
AI tools available directly in the terminal — no GUI required:

| Command | Description |
|---------|-------------|
| `psask` | Ask the active AI profile a direct question |
| `pschat` | Persistent chat session with conversation history |
| `pscmd` | Generate a shell command from a natural language description |
| `psfix` | Explain and fix the last terminal error |
| `psnext` | Suggest next pentest steps based on terminal history |
| `pstldr` | Summarize the last command output (TL;DR) |
| `psreport` | Generate a pentest report from terminal history |
| `psrag` | Query your RAG knowledge base |
| `psview` | Analyze a screenshot or image with AI vision |
| `pshelp` | List all available tools |

Supports 7 AI providers out of the box: **Ollama, OpenAI, Anthropic, Groq, Gemini, OpenRouter, HuggingFace**. Switch between them without leaving the app.

### RAG Knowledge Base
- Index your own notes, writeups, documentation, and PDF files
- Powered by ChromaDB + fastembed — runs fully offline
- Choose from 30+ embedding models grouped by category: English, Multilingual, Language-specific, Code, and Vision/Multimodal
- Optional reranking with 6 reranker models for improved result precision
- Configurable file extension filter (PDF, TXT, MD, RST, CSV, JSON, XML, YAML, code files, and more)
- Per-file include/exclude manager — selectively disable indexing of specific files
- Queries are automatically enriched with relevant context from your knowledge base
- File changes are tracked and re-indexed automatically via watchdog
- Indexing progress visible in the main UI status bar
- Dedicated RAG tab in AI Settings for full configuration

### Voice Interface
- Wake word detection — say **"Hey Jarvis"** to activate
- Speech-to-text transcription via Faster-Whisper (tiny model, CPU, ~75 MB)
- AI generates a command from your speech
- Voice confirmation loop — say "accept" or "cancel"
- Optimized for virtual machines (queue-based audio buffering, no xruns)

### Script Manager
- Launch, organize, and document Python scripts from a GUI
- Automatic help/docstring extraction
- Per-script execution history, notes, and favorites
- Dependency detection with in-app package installation

### File Viewer
- Syntax highlighting for 500+ languages via Pygments
- CSV and TSV files rendered as interactive sortable tables
- PDF files rendered with page navigation
- Audio and video files playable directly in the app
- Metadata and EXIF extraction via exiftool (GPS, codec info, camera data)
- Game files (`.game`) with dedicated viewer
- Chunked loading for large files
- Built-in search with regex support

### Nmap Integration
- Save and reuse scan profiles (`.psnmap` format)
- Full scan history with timestamps
- WebMap visualization via Docker

### AI Chat Panel
- Embedded web panel for Open WebUI or any OpenAI-compatible frontend
- Run and manage Docker-based LLM containers from the app
- Supports Ollama CLI profiles with custom parameters

### Additional Panels
- **Notes** — persistent side notes, auto-saved
- **Snippets** — reusable code/command snippets
- **Observable Variables** — real-time display of tracked shell variables
- **Mode Profiles** — terminal environment presets for different tasks

### Themes & Customization
PurrSh3ll ships with a large collection of built-in color themes and allows full visual customization — colors, fonts, and layout. The welcome screen (text, image, background) is editable directly from the UI with a double-click.

<img src="docs/images/cool_themes.png" width="900"/>

---

## Who Is It For?

| Audience | Key value |
|----------|-----------|
| **Penetration testers** | Local AI, pentest report generation, RAG over engagement notes |
| **CTF players** | `psnext`, `pscmd`, terminal history awareness, embedded CTF games |
| **Security students** | `psask`, `pschat`, knowledge base that grows with you |
| **Bug bounty hunters** | Organized notes, `psreport`, multi-provider AI |

PurrSh3ll is designed to grow with you — from learning to professional engagements.

---

## Requirements

- **OS:** Kali Linux (recommended), Debian/Ubuntu
- **Python:** 3.10+
- **Voice (optional hardware):** microphone

All other dependencies (PyQt6, QTermWidget, Ollama, Docker, etc.) are installed by `install.sh`.

**RAM usage:**

| Configuration | RAM |
|---------------|-----|
| App only (idle to multiple tabs + browser) | 200 MB – 1 GB |
| + RAG embedding model (during indexing) | +90 MB – 2.3 GB (depends on model) |
| + RAG reranking model (during reranking) | +100 – 400 MB (depends on model) |
| + Voice (during recognition) | +300 – 600 MB |
| + Open WebUI (Docker) | +500 MB – 1 GB |
| + WebMap (Docker) | +200 – 400 MB |
| Full stack with a large LLM model (~8B) | ~12 GB+ |

---

## Installation

PurrSh3ll ships with an interactive installer that lets you choose exactly which components to install.

```bash
bash install.sh          # interactive — pick components via checklist
bash install.sh --auto   # non-interactive — install everything
```

The core app, Python packages, and QTermWidget are always installed. Optional components you can select:

| Component | Description |
|-----------|-------------|
| **Ollama** | Local LLM inference server |
| **aichat** | CLI frontend for LLMs (multi-provider) |
| **Docker** | Container runtime |
| **Open WebUI** | Web UI for Ollama (Docker image) |
| **WebMap** | Nmap result visualizer (Docker image) |
| **Voice support** | Microphone, portaudio, Faster-Whisper |
| **AI Skills** | `awesome-claude-skills-security` + `claude-code-pentest` |

> ☕ **Note:** A full installation with all components may take **15–40 minutes** depending on your internet speed. Ollama and Docker images are downloaded during the process. Grab a big coffee — you'll need it.

### Disk space requirements

| Variant | Approx. size |
|---------|-------------|
| Core only (no voice) | ~1.8 GB |
| Core + voice | ~1.9 GB |
| Core + embedding model | ~2.0 GB |
| Full (no voice, no embed model) | ~5.3 GB |
| Full (no voice) | ~5.5 GB |
| Full + voice | ~5.6 GB |

> Sizes include Python venv (~1.4 GB, dominated by PyQt6 + onnxruntime) and Docker images for Open WebUI and WebMap (~3 GB combined). The embedding model (`paraphrase-multilingual-MiniLM-L12-v2`, ~220 MB) is optional during install — if skipped it is downloaded automatically on first RAG use. Ollama LLM models are **not** included — each model is downloaded separately on demand (typically 2–8 GB per model).

### After installation

```bash
# Start Ollama (Full only)
ollama serve

# Pull a model (Full only)
ollama pull llama3.2

# Launch PurrSh3ll
purrsh3ll
```

> **Note:** A full `requirements.txt` with pinned versions will be added in the next release.

---

## Quick Start

```bash
# Ask AI a question directly from the terminal
psask "what is a SSRF vulnerability?"

# Generate a command from natural language
pscmd "find all SUID binaries on the system"

# Get AI suggestion for the next pentest step
psnext

# Summarize last command output
pstldr

# Query your knowledge base
psrag "how to enumerate SMB shares"

# See all available tools
pshelp
```

---

## Project Structure

```
purrsh3ll/
├── main.py                    # Entry point
├── core/
│   ├── controller.py          # Central singleton controller
│   ├── mixins/                # UI and terminal logic mixins
│   ├── rag/                   # RAG engine (chunker, embedder, indexer)
│   ├── voice/                 # Voice pipeline (wake word → STT → AI)
│   └── stylesheets/           # Modular QSS theme system
├── gui/
│   ├── builders/              # UI builder functions
│   ├── widgets/               # Custom Qt widgets
│   └── panels/                # Side panel widgets
├── file_loaders/              # Polymorphic file viewer (50+ formats)
├── appdata/
│   ├── terminal_modules/      # AI CLI tools (psask, pscmd, psrag…)
│   ├── agent_modes/           # Pentest and CTF agent skill sets
│   └── themes.json            # Theme definitions
└── appmodules/
    ├── BrainDump/             # Default RAG knowledge base
    ├── Cyb3rBreak/            # Embedded CTF games (8 games)
    └── Cyb3rCollector/        # Organized data collection (listeners, stagers, reports)
```

<img src="docs/images/ai_and_opensource.png" width="900"/>

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| GUI | PyQt6, QTermWidget |
| Vector DB | ChromaDB |
| Embeddings | fastembed (30+ models: English, Multilingual, Code, Vision) |
| STT | Faster-Whisper (tiny, CPU int8) |
| Wake word | OpenWakeWord |
| Audio | sounddevice, scipy, mutagen |
| PDF | PyMuPDF (fitz) |
| AI inference | ctranslate2, onnxruntime |
| File watching | watchdog |
| Web panel | PyQt6-WebEngine |

---

## Roadmap

PurrSh3ll is under active development. This is not the final form.

I have more ideas than time — building this solo alongside a full-time job means progress is steady but not instant. What's coming:

- **Function calling & agentic loops** — AI that actually executes actions, not just suggests them
- **MCP client support** — connect to the growing ecosystem of Model Context Protocol servers
- **Deeper pentest automation** — multi-step AI agents for recon, enumeration, and reporting
- **Better multi-agent workflows** — specialized agents collaborating on complex tasks

I’m aware there are still areas that need improvement, such as widget colors, some untested tools, and parts of the UI. I have these in mind and will be addressing them over time.

> **Note:** I have not yet tested the integration with paid API providers such as Anthropic and OpenAI. These providers are implemented based on their official API documentation, but end-to-end testing with real API keys has not been performed. If you encounter issues, please open an issue.

If any of this sounds useful to you — star the repo, open an issue, or contribute. Every bit of feedback helps prioritize what gets built next.

---

## License

This project is licensed under the **GNU General Public License v3.0**.

See [LICENSE](LICENSE) for the full text.

Because PurrSh3ll uses PyQt6 (GPL v3), any distribution must comply with GPL v3.
If you need to embed PurrSh3ll in a proprietary product, contact us for a commercial licensing arrangement.

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

---

## Acknowledgements

- [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) — Qt6 bindings for Python (GPL v3)
- [QTermWidget](https://github.com/lxqt/qtermwidget) — terminal emulator widget for Qt
- [Ollama](https://github.com/ollama/ollama) — local LLM runtime
- [Open WebUI](https://github.com/open-webui/open-webui) — web frontend for local models
- [OpenWakeWord](https://github.com/dscripka/openWakeWord) — wake word detection
- [Faster-Whisper](https://github.com/SYSTRAN/faster-whisper) — efficient Whisper implementation
- [ChromaDB](https://github.com/chroma-core/chroma) — vector database
- [WebMap](https://github.com/SabyasachiRana/WebMap) — Nmap result visualization
- [fastembed](https://github.com/qdrant/fastembed) — lightweight, fast embedding library
- [Pygments](https://github.com/pygments/pygments) — syntax highlighting for 500+ languages

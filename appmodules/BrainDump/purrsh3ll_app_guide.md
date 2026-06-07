# PurrSh3ll — Application Guide

PurrSh3ll is an AI-powered desktop terminal environment for penetration testers, CTF players, and security learners. It runs on Kali Linux and Debian/Ubuntu. It combines a multi-tab terminal, local AI assistant, RAG knowledge base, voice interface, file viewer, and script manager in a single application.

---

## What PurrSh3ll Is

PurrSh3ll is a PyQt6 desktop application. It is designed to keep all security tools, notes, and AI assistance in one window without sending sensitive data to the cloud. The application is local-first — all AI can run fully offline using Ollama or other local providers.

---

## Terminal

PurrSh3ll has a built-in multi-tab Zsh terminal. Each tab is an independent shell session.

Features of the terminal:
- Open multiple terminal tabs simultaneously, each with its own environment
- Rename terminal tabs by double-clicking the tab label
- Zoom in and out per tab
- Set custom environment variables per tab
- All commands are logged automatically to a JSONL file with timestamps and exit codes
- When a command fails, an error overlay appears with options to Explain, Fix, or Analyze the error using AI
- Observable Variables panel shows real-time values of tracked shell variables
- Mode Profiles allow saving and switching terminal environment presets for different tasks
- Terminal sessions are restored on application restart

---

## AI CLI Tools

These commands are available directly inside the PurrSh3ll terminal. They do not require opening any GUI dialog.

| Command | What it does |
|---------|-------------|
| `psask` | Ask the active AI profile a question |
| `pschat` | Start a persistent chat session with conversation history |
| `pscmd` | Describe what you want to do in plain language — get a shell command |
| `psfix` | Explain and fix the last terminal error |
| `psnext` | Get AI suggestion for the next penetration testing step based on terminal history |
| `pstldr` | Summarize the last command output (TL;DR) |
| `psreport` | Generate a penetration testing report from terminal history |
| `psrag` | Query the RAG knowledge base |
| `psview` | Analyze a screenshot or image using AI vision |
| `pshelp` | List all available AI CLI tools |

To use any of these commands, type them directly in the terminal. For example: `psask "what is a buffer overflow?"` or `pscmd "list all open ports on 192.168.1.1"`.

---

### psask — ask the AI a question

Ask the active AI profile a single question and get a direct answer.

```
psask "what is a SSRF vulnerability?"
psask "explain the difference between bind and reverse shell"
psask -m llama3.2 "what is privilege escalation?"
psask --rag "how to enumerate SMB shares"
psask --rag -n 10 "lateral movement techniques"
```

Flags:
- `-m <model>` — override the model from the active profile
- `--rag` — enrich the prompt with relevant chunks from the knowledge base
- `-n <N>` — number of RAG chunks to include (default: 5, used with `--rag`)

---

### pschat — persistent chat session

Start a multi-turn conversation with the AI. History is preserved between runs.

```
pschat "let's analyze this target: 10.10.10.5"
pschat --new
pschat --history
pschat --clear
pschat --rag "what does my knowledge base say about SMB?"
pschat -m gemma3 "continue our analysis"
```

Flags:
- `--new` — clear history and start a new session
- `--clear` — clear history and exit without starting a session
- `--history` — show the current conversation history
- `--rag` — enrich the message with RAG context
- `-n <N>` — number of RAG chunks (default: 5)
- `-m <model>` — override the model

---

### pscmd — generate a shell command from a description

Describe what you want to do in plain language and get the exact shell command.

```
pscmd "find all SUID binaries on the system"
pscmd "list open ports on 192.168.1.1 with service detection"
pscmd "compress the /var/log directory to a tar.gz archive"
pscmd -m qwen3 "encode the string hello in base64"
```

Flags:
- `-m <model>` — override the model

---

### psfix — explain and fix the last terminal error

Reads the last failed command from terminal history and sends it to AI for explanation or fix.

```
psfix
psfix --explain
psfix --analyze
psfix -m llama3.2
```

Flags:
- `--explain` — explain why the command failed without suggesting a fix
- `--analyze` — deep mode with terminal history context and current directory
- `-m <model>` — override the model

---

### psnext — suggest the next penetration testing step

Reads terminal history and suggests the most promising next moves based on what has been done so far.

```
psnext
psnext --target 192.168.1.0/24
psnext -m llama3.2
```

Flags:
- `--target <TARGET>` — specify the target IP, hostname, or range for better suggestions
- `-m <model>` — override the model

---

### pstldr — summarize command output (TL;DR)

Summarize the last command output, a file, or any piped text.

```
pstldr
pstldr /var/log/syslog
pstldr --tail /var/log/syslog
pstldr "some long text here"
cat nmap_output.txt | pstldr
pstldr -m gemma3 report.txt
```

Flags:
- `--tail` — read from the end of the file instead of the beginning (useful for logs)
- `-m <model>` — override the model

---

### psreport — generate a penetration testing report

Filters terminal history for security-relevant commands and generates a structured Markdown or HTML report. Reports are saved to `appmodules/Cyb3rCollector/reports/`.

```
psreport
psreport --deep
psreport --full
psreport --verbose
psreport --format html
psreport --target 192.168.1.0/24
psreport --title "Internal Network Pentest"
psreport --target 10.10.10.5 --format html --verbose
```

Flags:
- `--deep` — Map-Reduce mode: chunks full history and extracts findings per chunk (N+1 LLM calls, slower but thorough)
- `--full` — include all history without smart-filtering for pentest keywords
- `--verbose` — stream the report to the terminal as it is generated
- `--format md|html` — output format (default: md)
- `--target <TARGET>` — target IP or range shown in report header
- `--title <TITLE>` — custom report title
- `-m <model>` — override the model

---

### psrag — query the knowledge base

Search the RAG knowledge base and get an AI answer enriched with relevant document chunks.

```
psrag "how to enumerate SMB shares"
psrag "what is BloodHound used for"
psrag "lateral movement techniques"
```

The query is embedded, matched against indexed documents, and the most relevant chunks are passed to the AI for a context-aware answer.

---

### psview — analyze a screenshot or image with AI vision

Send an image to the active AI profile and get a security-focused analysis. Requires a vision-capable model (e.g., llava, gemini-pro-vision, gpt-4o).

```
psview screenshot.png
psview /tmp/scan.png "what services are running?"
psview screenshot.png --cmd
psview screenshot.png --next
psview -m gpt-4o screenshot.png
```

Flags:
- `--cmd` — analyze the image and paste the best suggested command directly into the terminal
- `--next` — analyze the image and run a psnext-style suggestion using full history
- `-m <model>` — override the model (must support vision)

Supported image formats: PNG, JPG, JPEG, WEBP, GIF.

---

### psopen — open a file in PurrSh3ll from the terminal

Open any file in the PurrSh3ll file viewer directly from the terminal without using the module tree in the GUI.

```
psopen notes.md
psopen /tmp/report.txt
psopen /tmp/exploit.py
psopen -f /tmp/data.json -m json
psopen --help
```

Flags:
- `-f, --file <file>` — path to the file to open
- `-m, --mode <mode>` — override the viewer mode (e.g., py, sh, js, json, md, txt)
- `-h, --help` — show help

If the path is a directory, it is opened in the system file manager.

---

### pshelp — list all available tools

```
pshelp
```

Displays all available `ps*` commands with short descriptions.

---

## AI Providers

PurrSh3ll supports 7 AI providers. You can switch between them without restarting the application.

Supported providers:
- **Ollama** — local LLM inference, fully offline
- **OpenAI** — GPT models via API
- **Anthropic** — Claude models via API
- **Groq** — fast inference via Groq API
- **Google Gemini** — Gemini models via API
- **OpenRouter** — access to many models via single API
- **HuggingFace** — HuggingFace inference API

To configure providers and API keys, go to: **File → AI Settings → Profiles tab**.

You can create multiple profiles per provider and switch the active profile from the AI Settings dialog or from the terminal.

---

## RAG Knowledge Base

RAG stands for Retrieval-Augmented Generation. PurrSh3ll has a built-in RAG system that indexes your documents and enriches AI queries with relevant content from your notes.

How it works:
- Documents are split into chunks and converted to vector embeddings
- When you run `psrag "your question"`, the system finds the most relevant chunks and passes them to the AI
- The AI answers based on your documents, not just its training data

Configuration is available in **File → AI Settings → RAG tab**.

### Knowledge Base Location

Two modes are available:
- **BrainDump** — the default folder inside the application (`appmodules/BrainDump/`). This is where this file is stored.
- **Custom** — any folder on your system, set via the Browse button in RAG settings.

### Supported File Types for Indexing

By default, PurrSh3ll indexes: PDF, TXT, MD, RST, CSV files.

Additional formats can be enabled in RAG settings under Index Extensions: JSON, XML, YAML, YML, TOML, Python, JavaScript, TypeScript, Shell scripts, HTML.

### Embedding Models

PurrSh3ll supports 30+ embedding models via fastembed. Models are grouped by category:
- **English** — bge-small-en-v1.5, bge-base-en-v1.5, bge-large-en-v1.5, all-MiniLM-L6-v2, mxbai-embed-large-v1, arctic-embed models, jina-embeddings-v2-base-en, and more
- **Multilingual** — paraphrase-multilingual-MiniLM-L12-v2 (50+ languages), paraphrase-multilingual-mpnet-base-v2 (50+ languages), multilingual-e5-large (94+ languages), jina-embeddings-v3 (89 languages), nomic-embed-text models
- **Language-specific** — jina-embeddings-v2-base-de (German), jina-embeddings-v2-base-es (Spanish), jina-embeddings-v2-base-zh (Chinese), bge-small-zh-v1.5 (Chinese)
- **Code** — jina-embeddings-v2-base-code (30 programming languages)
- **Vision / Multimodal** — jina-clip-v1, clip-ViT-B-32-text

Important: choose a model that supports the language of your documents. Using an English-only model with non-English documents will produce poor or no search results.

### Reranking

Optional reranking re-scores search results for better precision. Enable it in RAG settings. Available rerankers:
- ms-marco-MiniLM-L-6-v2 (English, 80 MB, fast)
- ms-marco-MiniLM-L-12-v2 (English, 120 MB)
- jina-reranker-v1-tiny-en (English, 130 MB)
- jina-reranker-v1-turbo-en (English, 150 MB)
- bge-reranker-base (Chinese + English, 1.04 GB)
- jina-reranker-v2-base-multilingual (26+ languages, 1.11 GB) — the only multilingual reranker in the list

### Per-File Exclusion

In RAG settings under Indexed Files, you can uncheck individual files to exclude them from indexing without deleting them.

### Automatic Indexing

When "Enable automatic indexing" is turned on, PurrSh3ll watches the knowledge base folder and re-indexes any file that is added, modified, or removed. This happens in the background.

---

## Voice Interface

PurrSh3ll has a voice interface that listens for a wake word and converts speech to a terminal command.

How to use:
1. Say **"Hey Jarvis"** to activate
2. Speak your command or question
3. PurrSh3ll transcribes your speech and generates a command using AI
4. Say "accept" to run it or "cancel" to discard

The speech-to-text engine is Faster-Whisper (tiny model, ~75 MB, runs on CPU). Wake word detection uses OpenWakeWord. The system is optimized for virtual machines with queue-based audio buffering.

Voice support must be installed separately. If it is not working, check that portaudio and a microphone are available.

---

## File Viewer

PurrSh3ll has a built-in polymorphic file viewer. When you open a file from the module tree, it is displayed in a viewer appropriate for its type.

Supported categories:
- **Code** — Python, JavaScript, TypeScript, C, C++, Java, C#, Go, Rust, PHP, Ruby, Perl, Lua, Bash, Shell, PowerShell, Batch, HTML, Assembly, and more — with syntax highlighting via Pygments (500+ languages)
- **Data** — JSON, XML, YAML, TOML, INI, SQL
- **Markup** — Markdown (rendered), reStructuredText
- **Documents** — PDF with page navigation and metadata
- **Spreadsheets** — CSV and TSV as interactive sortable tables
- **Media** — Audio and video files playable directly in the app
- **Metadata** — EXIF, GPS coordinates, codec information extracted via exiftool

The viewer supports chunked loading for large files, built-in search with regex, and metadata display.

---

## Script Manager

The Script Manager lets you run and organize Python scripts from a GUI panel.

Features:
- Browse and launch Python scripts from a visual interface
- Docstrings and help text are automatically extracted and displayed
- Per-script execution history
- Per-script notes
- Favorites list for quick access
- Automatic dependency detection with in-app package installation
- Scripts in the `usermodules/` folder are watched and reloaded automatically on file change

To access the Script Manager, open a Python script from the module tree.

---

## Nmap Integration

PurrSh3ll has built-in Nmap scan management.

Features:
- Save scan profiles and reuse them
- Full scan history with timestamps
- Scan results stored in the Cyb3rCollector module
- WebMap visualization for scan results (requires Docker)

---

## AI Chat Panel

The AI Chat panel is an embedded web view inside PurrSh3ll.

It supports:
- Open WebUI — a full-featured web interface for local LLMs (requires Docker)
- Any OpenAI-compatible web frontend
- Docker container management for LLM services directly from the app
- Ollama CLI profile support with custom parameters

To access: click the Chat panel button or use the View menu.

---

## Side Panels

PurrSh3ll has several side panels accessible from the main interface:

- **Notes** — persistent freeform notes, auto-saved
- **Snippets** — reusable code and command snippets stored as JSON
- **Observable Variables** — real-time display of tracked shell variables from the terminal
- **Mode Profiles** — saved terminal environment presets
- **Favorites** — favorite scripts for quick access
- **History** — script execution history

---

## Settings

### Application Settings (File → Settings)

- Window size and position
- UI options

### AI Settings (File → AI Settings)

The AI Settings dialog has three tabs:

**Settings tab** — LLM backend configuration:
- Select provider and model
- Set API keys and endpoints
- Configure Ollama CLI parameters
- Set system prompt and skills

**RAG tab** — Knowledge base and embedding configuration:
- Knowledge base location (BrainDump or custom path)
- Embedding model selection
- Reranking on/off and reranker model
- Index extensions filter
- Indexed files manager
- Automatic indexing toggle
- Manual reindex and delete vector DB buttons

**Profiles tab** — Manage multiple AI provider profiles:
- Create, edit, delete profiles
- Each profile stores provider, model, API key, endpoint, and parameters
- Switch active profile per module

---

## Application Modules

### BrainDump

The default RAG knowledge base folder. Store your notes, writeups, and PDF documents here to make them searchable via `psrag`. This file (`purrsh3ll_app_guide.md`) is part of BrainDump.

### Cyb3rBreak

Eight embedded CTF mini-games: Space Race, Pong, Tic Tac Toe, Pacman, Simple Racer, Space Invaders, Snake, Tetris, Breakout. Access via the module tree.

### Cyb3rCollector

Organized data collection storage for red team operations:
- **Listeners** — malware stagers and payloads
- **Stagers** — payload delivery configurations
- **Reports** — penetration testing reports
- **WebMap** — Nmap scan visualizations

### Tools

Built-in tool configurations accessible from the module tree.

---

## Themes and Customization

PurrSh3ll ships with a large collection of built-in color themes.

- Switch themes from the View menu or settings
- Full visual customization: colors, fonts, layout
- Welcome screen (text, image, background) is editable by double-clicking it
- Theme changes apply without restarting the application

---

## Installation

PurrSh3ll uses an interactive installer:

```bash
bash install.sh          # interactive — select components via checklist
bash install.sh --auto   # non-interactive — install everything
```

Optional components available during installation:
- **Ollama** — local LLM inference server
- **aichat** — CLI frontend for multiple LLM providers
- **Docker** — container runtime
- **Open WebUI** — web interface for Ollama (Docker image)
- **WebMap** — Nmap visualization (Docker image)
- **Voice support** — Faster-Whisper, portaudio, OpenWakeWord

Requirements: Kali Linux or Debian/Ubuntu, Python 3.10+, PyQt6, QTermWidget.

---

## Frequently Asked Questions

---

**How do I ask AI a question?**
Type `psask "your question"` in the terminal. For a conversation, use `pschat`.

---

**How do I add my notes to the knowledge base?**
Copy or create Markdown, PDF, or text files in `appmodules/BrainDump/` (or your custom path set in RAG settings), then click "Refresh index" in RAG settings or wait for auto-indexing if it is enabled.

---

**How do I query the knowledge base?**
Type `psrag "your question"` in the terminal. You can also enrich any `psask` or `pschat` query with RAG context by adding the `--rag` flag: `psask --rag "your question"`.

---

**How do I switch the AI provider?**
Go to **File → AI Settings → Profiles tab**, select or create a profile, and set it as active.

---

**How do I fix the last terminal error with AI?**
Type `psfix` in the terminal after the error. Or click the error overlay that appears automatically when a command fails.

---

**How do I generate a shell command from a description?**
Type `pscmd "what you want to do"` — for example `pscmd "find files larger than 100MB"` or `pscmd "list all listening TCP ports"`.

---

**I opened the AI Chat panel but I see a blank page or loading screen. What should I do?**
Open WebUI runs inside a Docker container and may take 30–60 seconds to start up, especially on first launch. Wait for the container to fully initialize before the web interface becomes available.

To check if the Open WebUI container is running, use:
```
docker ps | grep open-webui
```
If the container is not listed, start it from the AI Chat panel controls inside PurrSh3ll, or start it manually:
```
docker start open-webui
```
To check container logs for errors:
```
docker logs open-webui --tail 50
```

---

**The RAG search returns no results. What should I check?**
1. Open **File → AI Settings → RAG tab** and check the Indexed Files list. If it is empty, no documents have been indexed yet.
2. Click "Refresh index" to force a re-index of the knowledge base folder.
3. Check that the embedding model supports the language of your documents. An English-only model will not find content in other languages.
4. Check the Status field in RAG settings for error messages.
5. Make sure the file extensions of your documents are enabled in Index Extensions settings.

---

**The AI response is very slow or I get no response at all. Could it be the model size?**
Yes. When using Ollama with a local model, the model is loaded entirely into RAM (or VRAM). If the model is too large for your available memory, the system will swap it to disk which causes extreme slowness, or the request may time out with no response.

General guidelines:
- 8B parameter models require approximately 6–8 GB of free RAM
- 13B parameter models require approximately 10–12 GB of free RAM
- 70B parameter models require approximately 40–50 GB of free RAM or a capable GPU

To check available RAM: `free -h`
To check which Ollama model is loaded and its size: `ollama ps`
To list downloaded models: `ollama list`

If you have limited RAM, use a smaller model such as `llama3.2:3b`, `gemma3:4b`, or `qwen3:4b`. Cloud providers (Groq, Gemini, OpenRouter) do not have this limitation since inference runs on their servers.

**Recommended models for CPU-only machines:**

Fast models that work well on CPU with limited RAM (~3 GB free):

| Model | Ollama pull command | Notes |
|-------|--------------------|----|
| Qwen3 3B | `ollama pull qwen3:3b` | Very fast, strong reasoning |
| Gemma 3 4B | `ollama pull gemma3:4b` | Fast, good quality |
| Phi-3.5 Mini | `ollama pull phi3.5` | Compact, efficient |
| SmolLM3 3B | `ollama pull smollm3:3b` | Very lightweight |
| Llama 3.2 3B Instruct | `ollama pull llama3.2:3b` | Reliable general use |

Model with vision support (image analysis) — slightly slower on CPU but still usable:

| Model | Ollama pull command | Notes |
|-------|--------------------|----|
| fredrezones55/Gemma-4-Uncensored-HauhauCS-Aggressive | `ollama pull fredrezones55/Gemma-4-Uncensored-HauhauCS-Aggressive:e2b-SCN` | Supports image analysis via `psview`, runs on CPU |

Use `psview screenshot.png` to analyze images with the vision model.

---

**The voice interface does not work. What should I do?**
Check that voice support was installed during setup (portaudio19-dev, Faster-Whisper, OpenWakeWord). Verify that a microphone is connected and accessible. Voice is not available without the optional voice component.

Test microphone access: `arecord -l`

---

**How do I open a file in the PurrSh3ll viewer from the terminal?**
Use `psopen <file>`. For example: `psopen /tmp/report.txt` or `psopen notes.md`. If you want to force a specific viewer mode: `psopen -f file.txt -m md`.

---

**How do I add a new AI provider profile?**
Go to **File → AI Settings → Profiles tab**, click the `+` button, fill in provider, model, and API key, then save.

---

**How do I generate a pentest report?**
Type `psreport` in the terminal. PurrSh3ll reads your terminal history, filters security-relevant commands, and generates a Markdown report saved to `appmodules/Cyb3rCollector/reports/`. For a more thorough report use `psreport --deep`. To set a custom title and target: `psreport --title "My Engagement" --target 10.10.10.5`.

---

**How do I summarize a long command output?**
Run `pstldr` immediately after the command. Or pipe output directly: `cat file.txt | pstldr`. To summarize a log file from the end: `pstldr --tail /var/log/syslog`.

---

**How do I analyze a screenshot or image?**
Type `psview screenshot.png` in the terminal. The active AI profile must support vision (e.g., llava, gpt-4o, gemini-pro-vision). To get a command suggestion from the image: `psview screenshot.png --cmd`.

---

**Where are application logs stored?**
In `appdata/logs/` inside the application folder.

---

**Where are generated pentest reports saved?**
In `appmodules/Cyb3rCollector/reports/`. They can also be opened directly from the Cyb3rCollector module in the module tree.

---

**How do I see all available terminal commands?**
Type `pshelp` in the terminal.

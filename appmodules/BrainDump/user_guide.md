# PurrSh3ll — User Guide

![img.png](images/user_guide_1.png)

**PurrSh3ll** is an AI-powered desktop environment for penetration testers, CTF players, and security researchers. It combines a terminal emulator, AI assistant, RAG knowledge base, script manager, file viewer, and note-taking system into a single local-first interface — all AI can run fully offline via Ollama or another local provider, so sensitive client data never has to leave the machine.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Interface Layout](#interface-layout)
3. [Menus](#menus)
4. [Terminal](#terminal)
5. [AI Tools — ps* Commands](#ai-tools--ps-commands)
6. [Chat Panel](#chat-panel)
7. [RAG Knowledge Base](#rag-knowledge-base)
8. [Script Manager](#script-manager)
9. [Markdown Support](#markdown-support)
10. [File Viewer](#file-viewer)
11. [Environment Variables & Aliases](#environment-variables--aliases)
12. [Voice Control](#voice-control)
13. [Themes & Customization](#themes--customization)
14. [AI Settings](#ai-settings)
15. [Model Database](#model-database)
16. [Session & Behavior](#session--behavior)
17. [Maintenance & Data](#maintenance--data)

---

## Getting Started

Launch PurrSh3ll from the terminal or desktop shortcut:

```bash
purrsh3ll
```

On first launch the welcome screen is shown. Double-click it to customize the welcome text, image, or background.

Type `pshelp` in any terminal to see all available AI tools. Before the AI tools work, add a provider profile in **File → AI Settings → Profiles** and set one active.

---

## Interface Layout

The interface is divided into three main areas:

- **Top menu bar** — File, Edit, View, and Help menus (see [Menus](#menus))
- **Left panel** — Chat, Script Manager, Notes, File Viewer, Environment Variables
- **Center** — Terminal tabs and execution area
- **Right panel** — Secondary tools and output

The left and right panels can be resized by dragging the splitters. Layouts adapt to the current mode.

---

## Menus

**File**
- **Settings** — session and behavior options
- **AI Settings** — provider profiles, RAG, and LLM configuration
- **Open File** — open any file in the built-in viewer
- **Exit**

**Edit**
- **Command Palette** (`Ctrl+P`) — quick access to tools and actions
- **Tool Categories** — organize and browse the tool catalog
- **Update Model Database…** — refresh model context windows and function-calling support (see [Model Database](#model-database))
- **Erase all data…** — selectively wipe collected data (see [Maintenance & Data](#maintenance--data))

**View**
- **Change Theme** — pick from the built-in themes

**Help**
- **User Guide** — this document
- **Manual** — extended reference
- **Check for Updates** — check GitHub for a newer version (read-only; never modifies your install)
- **Licenses** — third-party licenses, copyright, and trademark notices
- **Health Check** — diagnose the environment

---

## Terminal

PurrSh3ll uses a real terminal emulator (QTermWidget / zsh). Multiple tabs are supported and can be managed directly from the tab bar. Each tab is an independent shell session with its own environment.

**Tab management:**
- Open a new tab using the `+` button in the tab bar
- Close a tab using the `×` button on the tab
- **Rename a tab** by double-clicking the tab label
- Adjust terminal font size with `Ctrl + Mouse Scroll`

**Isolated history** — the in-app terminals keep their own arrow-key history, isolated from your system `~/.zsh_history` (and vice versa), so app commands never pollute your normal shell history.

**Full session recording** — every terminal session is recorded automatically to `appdata/logs/terminal_history.db` (SQLite). This includes executed commands, outputs, exit codes, timestamps, phase tags (recon, scan, exploit…) and auto-extracted findings (credentials, hashes, CVEs, flags). Use `pshistory` to browse the database, and AI tools like `psfix`, `psnext`, and `psreport` use it automatically for context. When a command fails, an error overlay offers to Explain, Fix, or Analyze it with AI.

---

## AI Tools — ps* Commands

PurrSh3ll includes a suite of AI-powered terminal commands. All tools use the active AI provider configured in **File → AI Settings → Profiles**.

Type `pshelp` in any terminal to list all available tools:

[Run pshelp](action://run/command/pshelp%0A)

---

### psask — Ask AI

Ask the active AI profile a direct question.

```bash
psask "what is SSRF and how to exploit it"
psask "explain the output of this nmap scan: ..."
psask -p my-cloud-profile "what is privilege escalation?"
psask -r "how to enumerate SMB shares"
psask -r -n 10 "lateral movement techniques"
```

Flags:
- `-p, --profile <profile>` — override the active profile
- `-r, --rag` — enrich the prompt with relevant chunks from the knowledge base
- `-n, --top-n <N>` — number of RAG chunks to include (default: 5, used with `--rag`)

---

### pschat — Chat with AI

Start a persistent interactive chat session. History is preserved between runs.

```bash
pschat "let's analyze this target: 10.10.10.5"
pschat --new
pschat --history
pschat -c
pschat -r "what does my knowledge base say about SMB?"
pschat -p my-profile "continue our analysis"
```

Flags:
- `--new` — clear history and start a new session
- `-c, --clear` — clear history and exit
- `--history` — show current conversation history
- `-r, --rag` — enrich the message with RAG context
- `-n, --top-n <N>` — number of RAG chunks (default: 5)
- `-p, --profile <profile>` — override the active profile

---

### pscmd — Command Generator

Describe what you want to do in plain English and get the shell command.

```bash
pscmd "find all SUID binaries on the system"
pscmd "scan ports 80 and 443 on 192.168.1.0/24 with nmap"
pscmd "compress the /var/log directory to a tar.gz archive"
pscmd -p my-profile "list all listening TCP ports"
```

Flags:
- `-p <profile>` — override the active profile

---

### psfix — Error Explainer

Reads the last failed command from terminal history and asks the AI to explain the error and suggest a fix. When the failed command was itself a `ps*` tool, its usage help is added to the prompt so the model can correct the invocation.

```bash
psfix
psfix -e
psfix -a
```

Flags:
- `-e, --explain` — explain why the command failed without suggesting a fix
- `-a, --analyze` — deep mode with full terminal history and current directory context
- `-p, --profile <profile>` — override the active profile

---

### psnext — Pentest Advisor

Reads recent terminal history and suggests the most promising next steps for the current engagement.

```bash
psnext
psnext -t 192.168.1.0/24
psnext -r
```

Flags:
- `-t, --target <TARGET>` — specify the target IP, hostname, or range for better suggestions
- `-r, --rag` — enrich with knowledge base context
- `-n, --top-n <N>` — number of RAG chunks (default: 5, used with `--rag`)
- `-p, --profile <profile>` — override the active profile

Useful when you are stuck or want a second opinion on attack paths.

---

### psrag — RAG Query

Query your local knowledge base and receive an AI-synthesized answer enriched with relevant document chunks.

```bash
psrag "how to enumerate SMB shares"
psrag "SQL injection bypass techniques"
psrag -n 10 "lateral movement techniques"
psrag -s "how to enumerate subdomains"
```

Flags:
- `-n, --top-n <N>` — number of context chunks to retrieve (default: 5)
- `-s, --show-sources` — print source filenames and relevance scores before the answer
- `-H, --host <URL>` — provider host/base URL override
- `-p, --profile <profile>` — override the active profile

---

### psreport — Pentest Report Generator

Generate a structured Markdown or HTML pentest report from terminal history. Reports are saved to `appmodules/Cyb3rCollector/reports/`.

```bash
psreport
psreport -d
psreport --full
psreport -v
psreport -f html
psreport -t 192.168.1.0/24
psreport -T "Internal Network Pentest"
psreport -t 10.10.10.5 -f html -v
```

Flags:
- `-d, --deep` — Map-Reduce mode: processes full history in chunks (N+1 LLM calls, thorough)
- `--full` — include full history without smart-filtering for pentest keywords
- `-v, --verbose` — stream the report to terminal while saving
- `-f, --format md|html` — output format (default: md)
- `-t, --target <TARGET>` — target IP or range shown in report header
- `-T, --title <TITLE>` — custom report title
- `-p, --profile <profile>` — override the active profile

---

### pstldr — TL;DR Summarizer

Summarize the last command output, a file, or piped input.

```bash
pstldr
pstldr report.txt
pstldr --tail /var/log/syslog
pstldr --tail 8000 /var/log/syslog
nmap -sV 10.10.10.1 | pstldr
pstldr -p my-profile report.txt
```

Flags:
- `--head [N]` — send only the first N characters to the model (default: 4000)
- `--tail [N]` — send only the last N characters to the model (default: 4000, useful for logs)
- `-p, --profile <profile>` — override the active profile

---

### psview — Image / Screenshot Analyzer

Send a screenshot or image to a vision-capable AI model for analysis. Requires a vision-capable model (e.g., llava, gpt-4o, gemini vision, or a multimodal Ollama model).

```bash
psview screenshot.png
psview /tmp/scan.png "what services are running?"
psview screenshot.png --cmd
psview screenshot.png --next
psview -p gpt-4o screenshot.png
```

Flags:
- `-c, --cmd` — analyze the image and paste the best suggested command into the terminal
- `-N, --next` — analyze the image and suggest next pentest steps using full history
- `-p <profile>` — override the active profile (must support vision)

Supported formats: PNG, JPG, JPEG, WEBP, GIF. Analysis results are saved to terminal history so `psnext` and `psreport` can use them.

---

### psopen — Open File in PurrSh3ll

Open any file in the PurrSh3ll viewer directly from the terminal. The viewer is selected automatically based on file extension. If the path is a directory, it opens in the system file manager.

```bash
psopen notes.md
psopen photo.tiff
psopen /tmp/capture.mp4
psopen -f /tmp/exploit.py
psopen -f /tmp/data -m txt
psopen --help
```

Flags:
- `-f, --file <file>` — path to the file to open
- `-m, --mode <mode>` — override viewer mode (useful when extension is missing or ambiguous)
- `-h, --help` — show help

---

### pshistory — Browse Session History

Browse the recorded terminal history database (commands, outputs, exit codes, findings). This is the SQLite log at `appdata/logs/terminal_history.db` that the other AI tools read for context.

---

### pshelp — List All Tools

```bash
pshelp
```

Displays all available `ps*` commands with short descriptions.

---

## Chat Panel

The Chat panel provides a GUI interface for interacting with AI. Three modes are available via the top selector:

| Mode | Description |
|------|-------------|
| **run + cli** | Launches a configured CLI tool (e.g. aichat, ollama run) in a terminal tab |
| **run + web** | Starts Open WebUI in a Docker container, opens in embedded browser |
| **connect** | Connects directly to any OpenAI-compatible API endpoint |

Configure AI profiles in **File → AI Settings → Profiles**.

> **Note:** When using **run + web** mode, Open WebUI runs inside a Docker container and may take **30–60 seconds** to start, especially on first launch. If you see a blank or loading page, wait for the container to fully initialize.
>
> To check if the container is running:
> ```bash
> docker ps | grep open-webui
> ```
> To check startup logs:
> ```bash
> docker logs open-webui --tail 50
> ```

---

## RAG Knowledge Base

PurrSh3ll includes a local Retrieval-Augmented Generation (RAG) system powered by ChromaDB and local embedding models.

**Knowledge base location (default):** `appmodules/BrainDump/`

Drop files (`.md`, `.txt`, `.pdf`, `.csv`, and more) into the BrainDump folder. The system indexes them automatically via a file watcher when auto-indexing is enabled. No manual action required.

> **Ask the AI about PurrSh3ll itself:** this guide (`user_guide.md`) also ships inside `appmodules/BrainDump/`, so once indexed you can ask `psask`, `pschat`, or `psrag` about any feature, tool, or workflow and get an answer grounded in the app's own documentation.

**Query the knowledge base** with `psrag` from any terminal tab, or enrich any AI query with `--rag`:

```bash
psrag "how to enumerate SMB shares"
psask --rag "what is pass-the-hash?"
```

**RAG Settings** (File → AI Settings → RAG tab):

- **Knowledge base** — switch between BrainDump and a custom folder path
- **Index extensions** — configure which file types are indexed (PDF, TXT, MD, CSV, JSON, YAML, code files, and more)
- **Indexed files** — view all indexed files; uncheck individual files to exclude them from indexing
- **Embedding model** — choose from 30+ models grouped by category (English, Multilingual, Language-specific, Code, Vision). Hover over a model name to see its size, languages, and use case
- **Re-ranking** — optionally enable reranking to improve result precision; choose from several reranker models
- **Automatic indexing** — enable to watch the folder and re-index on any file change
- **Refresh index** — manually trigger re-indexing
- **Delete vector DB** — remove all indexed data and start fresh

> **Important:** Choose an embedding model that supports the language of your documents. Using an English-only model with non-English documents will produce poor or no search results.

---

## Script Manager

Store, organize, and run Python (`.py`) and PurrSh3ll (`.purr`) scripts from one place.

**Features:**
- Automatic extraction of `--help` output and docstrings
- Per-script **notes** you can write and keep alongside each script
- Automatic installation of missing dependencies on run
- Scripts are watched for file changes and reloaded automatically
- **Full-screen code view** — click **code** to edit a script filling the whole layout; a Back button returns to the normal view

> Run history and favorites were removed from individual scripts — every command you run (including `psnmap` and `.purr` scripts) is already captured centrally in the session history, browsable with `pshistory`.

Scripts are stored in `usermodules/` and `appmodules/`.

---

## Markdown Support

PurrSh3ll renders Markdown files live and supports **action links** — clickable links inside a document that perform actions in the app:

```markdown
[Run nmap scan](action://run/command/nmap%20-sV%2010.10.10.1%0A)
[Switch to Cyberpunk theme](action://change/theme/Cyberpunk)
[Open AI Settings](action://open/window/ai_settings)
```

- `action://run/command/<url-encoded-cmd>` — run a command in a terminal (`%0A` = newline = execute)
- `action://change/theme/<name>` — switch theme
- `action://open/window/<id>` — open an app dialog (e.g. `ai_settings`, `settings`)

This makes it possible to build interactive runbooks and checklists directly inside your notes.

---

## File Viewer

Open and view files of various types directly within PurrSh3ll without leaving the application. Use `psopen` from any terminal tab to open a file in the viewer.

Supported content types:
- **Code** — Python, JavaScript, C/C++, Java, Go, Rust, Bash, PowerShell, HTML, and more — with syntax highlighting via Pygments
- **Data** — JSON, XML, YAML, CSV (interactive sortable tables), SQL, TOML
- **Documents** — PDF with page navigation
- **Media** — audio and video files playable in-app
- **Metadata** — EXIF, GPS, codec info extracted via exiftool
- **Archives** — listing of archive contents

---

## Environment Variables & Aliases

Manage shell environment variables and aliases through the GUI panel.

**Features:**
- Create, edit, and delete variables and aliases
- Apply to all terminal tabs simultaneously (configurable in Settings)
- Saved automatically and restored on next launch

---

## Voice Control

Voice control requires optional voice packages installed during setup (`--voice`).

**Capabilities:**
- **Wake word detection** — say "Hey Jarvis" to activate hands-free
- **Speech-to-text** — Faster-Whisper transcription (tiny model, CPU, ~75 MB)
- **Voice commands** — control the application or query AI by speaking
- **Voice confirmation** — say "accept" to run the generated command or "cancel" to discard

The voice button in the toolbar activates and deactivates listening.

---

## Themes & Customization

PurrSh3ll includes a large collection of built-in themes. Switch theme from **View → Change Theme** or click the links below:

- [Legacy Hacker](action://change/theme/Legacy%20Hacker)
- [Cyberpunk](action://change/theme/Cyberpunk)
- [Red Team](action://change/theme/Red%20Team)
- [Default](action://change/theme/default)

**Welcome screen customization:**
Double-click the welcome screen to open the editor. You can set:
- **Text** — custom welcome message (rotates hacker quotes every 10s by default)
- **Image** — display a custom image or GIF
- **Background** — set a background image or GIF for the welcome area

**Try it out:**

[Show available AI tools](action://run/command/pshelp%0A)

[Launch Matrix animation](action://run/command/cmatrix%20-ab%0A)

---

## AI Settings

Access via **File → AI Settings**. The dialog has three tabs: **Settings**, **RAG**, and **Profiles**.

### Settings Tab

Configure the LLM backend:

| Field | Description |
|-------|-------------|
| Provider | Local: `ollama`, `llamacpp`, `lmstudio`, `jan`, `koboldcpp`. Cloud: `openai`, `anthropic`, `groq`, `gemini`, `openrouter`, `mistral`, `together_ai`, `huggingface`, and more |
| Model | Model name (e.g. `llama3.2:3b`, `gpt-4o`, `claude-opus-4-8`) |
| URL | Base URL of the API endpoint |
| API Key | Stored securely in the system keyring |

**Fetch models:** in the Profiles tab you can fetch the live model list from the provider (some require the API key first). The **Context window** and **Function calling** shown for a model come from the local model database — keep it fresh with **Edit → Update Model Database…** (see [Model Database](#model-database)).

**Agent Mode:**
- **Agent Role** — defines the system prompt and workflow (e.g. `pentest_mode`, `ctf_mode`)
- **Skills Set** — loads a specific set of AI skills and context files

> **Note on Ollama context window:** Ollama serves `num_ctx`, which defaults to **4096 tokens** — commonly the effective limit on CPU-only or VM setups regardless of a model's architecture maximum. PurrSh3ll therefore treats Ollama as 4096 by default. If you have raised `num_ctx` (e.g. on a GPU), set a larger **context window override** on the profile.

> **Note on Ollama model size:** the model must fit in available RAM. If it is too large, responses are extremely slow or never arrive.
>
> | Model size | RAM required (approx.) |
> |------------|------------------------|
> | 3B params  | ~3 GB                  |
> | 8B params  | ~6–8 GB                |
> | 13B params | ~10–12 GB              |
> | 70B params | ~40–50 GB              |
>
> Check available RAM: `free -h` · Loaded model: `ollama ps` · Downloaded models: `ollama list`
>
> **Recommended models for CPU-only machines** (~3 GB free RAM): `gemma3:4b`, `qwen3:4b`, `llama3.2:3b`, `phi3.5`. Cloud providers (Groq, Gemini, OpenRouter) do not have this limitation.

### RAG Tab

Full RAG configuration — see the [RAG Knowledge Base](#rag-knowledge-base) section above.

### Profiles Tab

Create, edit, and delete AI provider profiles. Each profile stores provider, model, API key, endpoint, and custom parameters (including an optional context-window override). Multiple profiles can be created and switched between; one is set active.

---

## Model Database

PurrSh3ll ships a local model database (`appdata/model_ctx_registry.json`) that records each model's **context window** and whether it supports **function calling**. This drives what AI Settings displays and how much history the tools send.

Refresh it any time with **Edit → Update Model Database…**:

- Downloads the latest model data from the liteLLM public database — **no API key required**
- Backs up the current file first, then writes the update atomically
- Preserves curated defaults (e.g. Ollama's 4096 context tier)
- Reports how many models were updated per provider

Run it after new models are released so context windows and function-calling support stay accurate.

---

## Session & Behavior

Configurable in **File → Settings**:

| Setting | Description |
|---------|-------------|
| Restore session at start | Re-open terminal tabs from the previous session |
| Save environment variables at close | Persist env vars between sessions |
| Apply env vars to all terminals | Sync variables across all open tabs |
| Clear terminal history on exit | Wipe the SQLite history database on a clean exit |
| Clear notes on exit | Clear the notes panel on exit |
| Disable terminal history | Stop recording commands to the history database |
| Max history entries | Maximum number of entries kept in history |

> **Note:** "Clear terminal history on exit" only runs on a clean shutdown (confirm-exit → Yes). For a guaranteed wipe regardless of how the app closes, use **Edit → Erase all data…**.

---

## Maintenance & Data

**Edit → Erase all data…** lets you selectively and permanently delete collected data. Each category is a checkbox, so you keep full control:

- Command history database, script notes, notepad, chat sessions
- RAG vector index, saved images, logs
- Sidebar system variables, snippets, stored credentials
- Optionally remove all Docker containers created by the app

Type-to-confirm and a second confirmation guard the action. Stored credentials are removed from the system keyring and the local fallback file.

> **Privacy:** PurrSh3ll is local-first. API keys are kept in the system keyring (never in logs or history), `ps*` command output is isolated from reports, and secrets are redacted before anything is written to the tool log.

---

*PurrSh3ll is under active development. New features and modules are added regularly.*

# First Steps with PurrSh3ll

Welcome to PurrSh3ll. This guide walks you through the first things to set up after installation.

---

## 1. Configure an AI Profile

AI tools (`psask`, `pscmd`, `psnext`, etc.) require an active profile before they work.

Open **AI Settings** from the sidebar and add a profile. Two options:

**Option A — Local (fully offline)**

```bash
# Install Ollama (included in install_full.sh)
ollama serve

# Pull a model
ollama pull llama3.2        # ~2 GB, recommended starter
ollama pull llama3.2:1b     # ~0.8 GB, faster, less capable
```

Then in AI Settings: provider → **Ollama**, model → `llama3.2`, set as active.

**Option B — Cloud API (no local resources needed)**

Supported: **OpenAI, Anthropic, Groq, Gemini, OpenRouter, HuggingFace**

Groq is recommended for getting started — free tier, fast, no setup beyond an API key.

In AI Settings: provider → **Groq**, paste API key, pick a model, set as active.

---

## 2. Verify the Setup

Open a terminal tab and run:

```bash
psask "what is a reverse shell?"
```

If you get a response — you're ready.

**Common issues:**

| Problem | Fix |
|---------|-----|
| `no active profile` | Set a profile as active in AI Settings |
| `connection refused` (Ollama) | Run `ollama serve` first |
| `invalid api key` | Check the key in AI Settings |

---

## 3. Learn the ps* Tools

Run these one by one and watch what happens:

```bash
# Generate a shell command from natural language
pscmd "find all SUID binaries on the system"

# Summarize the output of the last command
pstldr

# If the last command failed — explain and fix it
psfix

# Suggest the next pentest step based on your terminal history
psnext

# Ask a direct question
psask "explain what /etc/passwd contains"

# Open a persistent chat session
pschat

# See all available tools
pshelp
```

---

## 4. Set Up the RAG Knowledge Base (Optional)

RAG lets `psask`, `pschat`, and `psrag` answer questions using your own notes and documents.

```bash
# Drop your files here — any text, Markdown, or code files
ls appmodules/BrainDump/
```

Files are indexed automatically via watchdog — no manual step needed.

```bash
# Query the knowledge base
psrag "how to enumerate SMB shares"
psrag --show-sources "common privesc techniques"
```

To add a new knowledge base or change the embedding model: **AI Settings → RAG**.

---

## 5. Personalize the App

- **Theme** — change from the top menu or sidebar; dozens of built-in themes (Legacy Hacker, Cyberpunk, Red Team, and more)
- **Welcome screen** — double-click anywhere on it to edit text, image, or background
- **Mode Profiles** — save terminal environment presets for different tasks (CTF, recon, reporting)
- **Snippets** — store reusable commands and code fragments

---

## 6. Voice Interface (Optional)

Requires `--voice` flag during installation.

Say **"Hey Jarvis"** to activate, then speak your command. PurrSh3ll transcribes it, generates a shell command, and asks you to confirm with "accept" or "cancel".

Enable the microphone button from the toolbar.

---

## usermodules/

This folder is yours. Place custom scripts, tools, or files here — they will appear in the file tree on the left and open in the built-in viewer. The folder is excluded from version control.

# First Steps with PurrSh3ll

Welcome to PurrSh3ll. This guide walks you through the first things to set up after installation.

---

## 1. Configure an AI Profile

AI tools (`psask`, `pscmd`, `psnext`, etc.) require an active profile before they work.

Open **AI Settings** from the sidebar and add a profile. Two options:

**Option A — Local (fully offline)**

Ollama is included in `install_full.sh`. **Click any line below to run it in a terminal:**

- [▶ ollama serve](action://run/command/ollama%20serve%0A) — start the local Ollama server (run this first)
- [▶ ollama pull llama3.2:1b](action://run/command/ollama%20pull%20llama3.2%3A1b%0A) — ~0.8 GB, very fast but not very bright (quick tests / weak hardware)
- [▶ ollama pull fredrezones55/Gemma-4-Uncensored-HauhauCS-Aggressive:e2b-SCN](action://run/command/ollama%20pull%20fredrezones55%2FGemma-4-Uncensored-HauhauCS-Aggressive%3Ae2b-SCN%0A) — uncensored + multimodal (understands images too), runs well even on CPU only
- [▶ ollama pull qwen2.5:7b](action://run/command/ollama%20pull%20qwen2.5%3A7b%0A) — ~4.7 GB, strong all-rounder for a typical 8 GB VRAM GPU

Then in AI Settings: provider → **Ollama**, pick the model you pulled, set as active.

**Option B — Cloud API (no local resources needed)**

Supported: **OpenAI, Anthropic, Groq, Gemini, OpenRouter, HuggingFace**

In AI Settings: provider → paste API key, pick a model, set as active.

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

**Click any example to run it in a terminal:**

- [▶ pscmd "find all SUID binaries on the system"](action://run/command/pscmd%20%22find%20all%20SUID%20binaries%20on%20the%20system%22%0A) — generate a shell command from natural language
- [▶ pstldr](action://run/command/pstldr%0A) — summarize the output of the last command
- [▶ psfix](action://run/command/psfix%0A) — if the last command failed, explain and fix it
- [▶ psnext](action://run/command/psnext%0A) — suggest the next pentest step from your terminal history
- [▶ psask "explain what /etc/passwd contains"](action://run/command/psask%20%22explain%20what%20%2Fetc%2Fpasswd%20contains%22%0A) — ask a direct question
- [▶ pschat](action://run/command/pschat%0A) — open a persistent chat session
- [▶ pshelp](action://run/command/pshelp%0A) — see all available tools

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

**Ask the AI about PurrSh3ll itself:** open **AI Settings → RAG** and click the **Index** button. Once indexing finishes, you can ask `psask`, `pschat`, or `psrag` about the app's entire functionality — every `ps*` tool, option, and workflow — and the LLM answers using the app's own bundled documentation.

---

## 5. Personalize the App

- **Theme** — change from the top menu or sidebar; dozens of built-in themes. Click to try one: [Legacy Hacker](action://change/theme/Legacy%20Hacker) · [Cyberpunk](action://change/theme/Cyberpunk) · [Red Team](action://change/theme/Red%20Team) · [Vaporwave](action://change/theme/Vaporwave) · [Default](action://change/theme/default)
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

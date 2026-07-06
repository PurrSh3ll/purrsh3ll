# Changelog

All notable changes to PurrSh3ll are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased] — v1.2.0

### Added

- **ps\* failure diagnostics log**: failed ps\* tools (`psrag`/`psai`/`psask`/`pschat`/`pscmd`/`pstldr`/`psreport`/`psview`/`psopen`/`pshelp`) now record their **exit code and Python traceback** to a dedicated `appdata/logs/pstools.log` — previously these ran as separate terminal subprocesses whose crashes left no trace in `app.log`. Written **only by the main process** via a private `purrsh3ll.pstools` logger (own `RotatingFileHandler`, 1 MB × 2, `propagate=False` so it never touches `app.log`/console), keeping the file a single writer and rollover-safe. Only the exit code + traceback are captured (never the tool's normal output or prompts), and a **secret-redaction filter** scrubs API keys / bearer tokens / `key=…` URL params before anything reaches disk. Non-failing runs write nothing
- **Snippets — run in a new or the current terminal**: running a snippet from the side panel now opens the run dialog with a "Run in current terminal" checkbox — unchecked (default) runs the snippet in a **new** terminal tab (named after the snippet, created via `_add_new_terminal_tab` which waits for the shell prompt before sending), checked sends it to the **current** terminal (the previous behavior). The dialog now always appears, even for snippets without `{PLACEHOLDER}` values, showing a command preview so the target choice is available for every snippet
- **Image viewer**: new file loader for images — supports PNG, JPG, GIF, BMP, WEBP, TIFF, SVG, ICO and other Qt-native formats; animated GIF/WEBP via QMovie; zoom toolbar (Fit / 1:1 / +/− / Ctrl+Scroll); Info dialog with EXIF metadata (exiftool) and MD5/SHA256 integrity hashes; static GIF/WEBP use SmoothTransformation for quality zoom; SVG rendered via QSvgRenderer, TIFF via Pillow fallback
- **Skills & agents**: added 5 MIT-licensed cybersecurity skill sets to the dropdown — `secskills` (16 skills + 6 subagents), `cybersecurity-claude-skills` (4 skills), `communitytools` (38 skills with reference docs), `claude-code-owasp` (OWASP Top 10:2025 + ASVS 5.0), `pentest-ai-agents` (36 specialised subagents)
- **Agent Configuration / AI Settings**: "Skills set" label renamed to "Skills & agents" — reflects that a set can contain both Claude Code skills (`.claude/skills/`) and subagents (`.claude/agents/`)
- **apply_agent_files**: skill sets with a `skills/` subfolder now deploy to `.claude/skills/`; sets with an `agents/` subfolder deploy to `.claude/agents/`; direct skill folders retain existing behaviour
- **psopen help**: updated with supported file type categories (any text or code file, PDF, images, audio, video) and improved `-m` usage description
- **AI Settings → Behavior**: new "Temperature" setting (replaces the earlier "Custom system prompt" row) — a checkbox + 0.0–2.0 spinbox controlling sampling randomness (0 = deterministic, higher = more random; default 0.8). Applies to every provider: in the ps* engine (`psai`/`psview`/`psfix`/`psnext`/`psreport`/`pscmd`/`pstldr`) it is injected per-provider — `options.temperature` for Ollama native, `temperature` for OpenAI-compatible and Anthropic; in **ai_chat** run mode it is baked into the temporary model's Modelfile (`PARAMETER temperature …`) alongside any system prompt. Advanced "Custom parameters" JSON with its own `temperature` still takes precedence. (`psrag` keeps its own separate LLM path and is unaffected.) The previously stored `custom_system` value is preserved on existing profiles but is no longer editable from this dialog
- **AI Settings → Settings**: "Max pschat turns" spinbox — configures how many past conversation turns `pschat` keeps in context (default 20, range 1–999)
- **AI Settings → Settings**: "Max terminal turns" spinbox — configures how many terminal history entries are sent to `psreport` (standard mode), `psfix --analyze` and `psnext` (default 40, range 1–999)
- **File tree**: drag-and-drop from system file manager now supported — files and folders are copied (not moved) to the drop target with a confirmation dialog; dropping on empty space copies to `usermodules/`
- **API providers**: added llamacpp (`localhost:8080`), LM Studio (`localhost:1234`), Jan (`localhost:1337`), koboldcpp (`localhost:5001`), Mistral, DeepSeek, xAI, Cerebras, Together AI, Perplexity, Fireworks AI
- **HuggingFace model fetch**: increased limit from 50 to 300 models
- **Startup**: third-party library noise suppressed on stdout/stderr (onnxruntime, chromadb, fastembed, HuggingFace, PIL)
- **uninstall.sh**: interactive uninstaller added — whiptail checklist to selectively remove venv, shortcuts, shell entries, user data, Docker images, Ollama models and app folder
- **requirements.txt**: added with full list of Python dependencies for reference
- **Agent modes**: renamed `ctf_mode` → `ctf` and `pentest_mode` → `pentest`; added `ctf_skills` and `pentest_skills` — lightweight CLAUDE.md files optimised for use with Claude Code skills and subagents; route each engagement phase to available `.claude/skills/` and `.claude/agents/` instead of inline cheat-sheets
- **Terminal history awareness**: all four agent CLAUDE.md files (`ctf`, `pentest`, `ctf_skills`, `pentest_skills`) now instruct the agent to read `./terminal_history.jsonl` before any task — gives the agent visibility into what the user has already executed in PurrSh3ll terminals
- **Goal file**: new "Goal" dropdown in Agent Configuration dialog and AI Settings → Settings; two built-in goal files (`ctf.md`, `pentest.md`) — each instructs the agent to collect required info from the user before acting and defines a stop condition for the session; the selected goal file is deployed alongside `CLAUDE.md` to the logs directory when an agent role is applied
- **SQLite terminal history database**: new `core/db/terminal_history_db.py` module with `TerminalHistoryDB` class — schema covers `commands` (ts, ts_end, duration_ms, terminal, cmd, exit_code, output, output_size, cwd), `command_tags` (many-to-many phase/finding tags), `findings` (port, credential, hash, flag, CVE, user, host), `targets`, `target_ports`; all commands now written to `appdata/logs/terminal_history.db` in parallel with JSONL; JSONL mechanism unchanged
- **pshistory**: new CLI tool (`appdata/terminal_modules/pshistory`) for querying the SQLite history database — `pshistory` (last 20 commands), `-n N` (last N), `--all` (full chronological history), `-q PATTERN` (search cmd and output), `--findings`, `--stats`, `--show ID` (full output of one command), `--clear` (delete all with confirmation), `--clear -y` (skip confirmation); IDs reset to 1 after `--clear`
- **PurrSh3ll tools excluded from SQLite history**: commands whose first word is `psfix`, `psnext`, `psreport`, `psrag`, `pshistory`, `pshelp`, `pstldr`, `psai`, `pscmd` or `psopen` are not written to the SQLite DB — keeps the DB clean for real engagement commands; JSONL is unaffected
- **Auto-tagger**: new `core/db/auto_tagger.py` module — on every `insert_command()` the first word of the command is looked up in `tool_categories.json`; matching tags are automatically written to `command_tags` via `add_tags()`; unknown tools produce no tags; JSON is loaded lazily and shared across terminals
- **pshistory `-t/--tag TAG`**: filter history by category tag (e.g. `pshistory -t recon`, `-t web -n 50`, `-t exploit --all`)
- **pshistory `--categories`**: list all categories defined in `tool_categories.json` with their label and how many commands are tagged in the DB
- **Tool Categories editor**: new dialog under Edit → Tool Categories — browse, add, edit and remove tool→category mappings stored in `appdata/tool_categories.json`; two-panel layout (category list left, tools table right); category filter, search bar, count in "All (N)" header; changes saved immediately; table colors match active theme
- **Tool Categories — Reset to Defaults**: "Reset to Defaults" button restores all tool and category mappings from `appdata/tool_categories_default.json` (built-in snapshot) with a confirmation dialog
- **Tool Categories — 249 tools, 19 categories**: shipped with a comprehensive default database covering recon (48), scan (22), web (27), smb (13), ftp (3), ssh (7), ldap (4), ad (31), exploit (11), privesc (10), lateral (17), crack (16), shell (10), network (28), cloud (5), forensics (11), re (8), wifi (22), other (8)
- **Output parser**: new `core/db/output_parser.py` — automatically extracts findings, targets and open ports from terminal output after every command; Priority 1 global patterns (zero false-positive): CVE IDs, NTLM hashes, Kerberos TGS/AS-REP tickets, CTF flags (HTB/THM/picoCTF/DUCTF/…), credentials from Hydra/Medusa/ncrack, kerbrute users and passwords, rpcclient user enumeration; Priority 2 tool-specific parsers: nmap/masscan/rustscan (hosts + open ports), netexec/nxc/crackmapexec (SMB hosts, credentials), nuclei (CVEs, vulnerabilities), feroxbuster/gobuster/ffuf (HTTP findings), nikto (findings), arp-scan (targets); results written to `findings`, `targets`, `target_ports` tables
- **pshistory `--targets`**: show all discovered targets with IP, hostname, OS guess and open port count
- **pshistory `--ports [IP]`**: show all open ports across all targets, or filtered to a specific IP
- **pshistory `--findings`**: show all auto-extracted findings (CVEs, credentials, hashes, flags, users, hosts)
- **pshistory help sections**: help text reorganized into four sections — BROWSING, SEARCH & FILTER, RECON DATA, MISC
- **DB output limit**: terminal command output stored in SQLite capped at 100 KB per entry — oversized outputs get a `[... output truncated at 100 KB ...]` notice appended; OutputParser always receives the full raw output before truncation so no findings are lost
- **History limit — Set button**: new "Set" button next to Max history entries in File → Settings; clicking shows a confirmation dialog warning about data loss, then saves the new limit and trims the DB oldest-first; "Default" button (resets to 10 000) also triggers the same confirmation flow
- **History limit — default raised**: default max history entries changed from 5 000 to 10 000
- **Clear terminal history on exit**: checkbox in File → Settings now also clears `terminal_history.db` (all commands, tags, findings, targets, ports) in addition to the existing `.jsonl` file removal
- **TerminalHistoryDB.trim_to_limit(n)**: new method — deletes the oldest commands (and orphaned tags) to enforce a maximum entry count; used by the Set button in Settings
- **TerminalHistoryDB.clear()**: new method — deletes all history data from the DB; used by "Clear terminal history on exit"
- **psreport — SQLite migration**: `psreport` no longer reads `terminal_history.jsonl`; reads `terminal_history.db` via SQLite — command filtering now uses `command_tags` (282 tools, 19 categories from `tool_categories.json`) instead of ~60 hardcoded `_TOOL_PATTERNS`; `_is_pentest_relevant()` retained as fallback for untagged commands; both standard and deep mode prepend `[ATTACK SURFACE]` + `[FINDINGS]` + `[PHASE COVERAGE]` intel header from structured tables; each history entry annotated with phase tags (e.g. `[recon, scan]`) so the model understands which phase each command belongs to; `--full` and `--deep` modes unchanged
- **DB output truncation — head+tail strategy**: replaced head-only 100 KB truncation with head+tail — first 60 KB (banner, config, early results) + `[... N bytes omitted ...]` + last 40 KB (errors, summaries, final findings); LLMs now always see both the context of what was run and the final result, critical for `psfix` diagnosing errors that appear at the end of long outputs
- **psnext — SQLite 3-layer structured prompt**: `psnext` no longer reads `terminal_history.jsonl`; instead it queries `terminal_history.db` and builds a structured prompt with three layers — `[ATTACK SURFACE]` (all discovered targets and open ports from `targets`/`target_ports` tables), `[FINDINGS]` (deduplicated credentials, users, hashes, flags, CVEs from `findings` table), `[PHASE COVERAGE]` (which pentest phases have been used and how many times, plus explicit `NOT YET` list of untried phases from `command_tags`), and `[RECENT SESSION]` (last N commands with output capped at 400 chars); `--target` filters the attack surface and findings to a specific IP; prompt is ~900 tokens for a typical HTB box with full attack surface visibility across the entire engagement, not just the last few commands
- **Settings → Window → Full window**: new "Full window" checkbox — when checked the application starts maximised; state persisted in `app_config.json` under `window.maximized`; toggling the checkbox also immediately maximises or restores the window
- **psnext — command deduplication**: `[RECENT SESSION]` layer now deduplicates commands before applying the limit — fetches `limit × 4` entries, removes duplicate `cmd` values keeping the most recent execution, then takes the last N; if the same nmap or gobuster command was run multiple times only the latest result is sent to the model
- **psreport — command deduplication**: `[TERMINAL HISTORY]` section deduplicates commands before applying the limit — after filtering (tags + fallback), keeps only the most recent execution of each unique command, then takes the last N in chronological order
- **psview `--next` — upgraded to psnext 3-layer prompt**: `--next` flag now sends the same structured context as `psnext` — `[ATTACK SURFACE]` + `[FINDINGS]` + `[PHASE COVERAGE]` + `[RECENT SESSION]` with deduplication and `_TERMINAL_HIST_LIMIT` limit; replaces the old flat 40-entry history with no structure; `hide_thinking` now also forwarded correctly
- **XML syntax highlighting**: `.xml` files now get Pygments syntax highlighting (via `XmlLexer`) like other code files — previously the XML loader was an empty `BaseFileLoader` subclass and rendered as plain text; follows the same convention as `sh_file.py`/`sql_file.py` (disabled above 1000 lines, colors follow the active theme)

- **psreport `-n/--notes FILE`**: new notes mode — send a pentester's text notes file to the LLM; the model generates a full report and inserts `<!-- PSEVIDENCE: <terms> -->` placeholders; the app resolves each placeholder with matching terminal commands and output from SQLite via OR-scored token search; placeholders with `min_score ≥ 2` required (prevents noise from single-token matches); each matched row injected at most once across the whole report (deduplication by row id); `max_results=2` per placeholder; evidence block rendered as fenced blockquote with timestamp and phase tags
- **psreport — evidence block formatting**: `\n\n` added before each injected evidence block so it renders on its own line instead of inline with the preceding sentence
- **psfix — function calling**: when `tools_user_override` or model default enables function calling, `psfix` sends a `fix_command` tool definition; if the tool call returns `None` it falls back to the text path; explain and analyze modes also use FC when enabled
- **psnext `-c/--cmd`**: new flag — outputs only the single best next command with no analysis; uses function calling when FC is enabled, otherwise redirects stdout+stderr to suppress streaming and extracts command via `_clean_command()`
- **psview `-c/--cmd`**: restored flag — outputs only the single best command from image analysis; FC path sends image in messages to `_run_llm_tool_call()`; text path suppresses streaming output
- **AI Settings → Profiles → Behavior**: new "Function calling" checkbox below "Override context" — shows detected model default in parentheses (`default: yes` / `default: no`); "Default" button resets override to `None`; override stored as `tools_user_override` in profile
- **model_ctx_registry.json**: added `tools_default` (bool) and `no_tools` (list of model patterns) fields per provider section — controls whether function calling is available for a given model by default
- **Voice button**: emoji changed to 🎧; width changed to 72 px; displays dynamic text based on `VoiceThread` state — `wake` (red) when idle/listening for wake word, `listening` (green) when recording, `processing` (blue) when sending to model, `🎧` (grey) on error
- **Voice — wake word sensitivity**: `_WAKEWORD_SCORE_THRESHOLD` lowered from `0.5` to `0.4` — the wake word ("Hey Jarvis") fired only when spoken loud and slow, with zero false positives observed, so the detection threshold was relaxed to trigger more easily
- **Voice — confirmation words `confirm`/`abort`**: the spoken words to accept/reject a generated command changed from `accept`/`cancel` to `confirm`/`abort` — short single words transcribed poorly on the tiny STT model and were dropped by the VAD; `confirm`/`abort` are multi-syllable and far apart phonetically, so the tiny model recognises them reliably (popup buttons relabelled `✓ Confirm` / `✗ Abort`, hint text updated)
- **Voice — nearest-match keyword recognition**: confirmation no longer requires an exact substring; `VoiceThread._classify_confirmation()` maps the transcript to an action by edit-distance similarity (`difflib`, threshold `0.7`) against each keyword plus its common tiny-model mishears (`conform`, `affirm`, `aboard`, `a board`, …), so a misrecognition still resolves to the right action; the STT decoder is also biased toward the keywords via `initial_prompt="confirm or abort"`, and the confirm phase records with a lower `_VAD_MIN_SPEECH_FRAMES` (3, ~240 ms) so a quick word isn't discarded as noise
- **Voice — confirmation retry feedback**: new `confirm_retry` state — when the confirm phase hears speech that isn't `confirm`/`abort` (or too short), the command popup turns amber with "Didn't catch that — say 'Hey Jarvis' then 'Confirm' or 'Abort'" instead of silently returning to idle
- **Startup layout — file/terminal split**: default vertical split between the file panel (top) and terminal panel (bottom) changed from ~71/29 to 55/45, giving the terminals more room on launch
- **Startup — Cyb3rCollector folder**: `appmodules/Cyb3rCollector/` (runtime data: listeners, stagers, webmap scans, reports) is now created by the controller at startup if missing, so the folder no longer needs a tracked `.gitkeep`
- **psreport — evidence deduplication**: `_resolve_placeholders` tracks injected row ids across the whole report; each terminal command appears at most once, preventing the same evidence block from repeating in every section; requires `min_score=2` (at least 2 matching tokens) to filter noise
- **Single-instance protection**: `main.py` uses `QLockFile` to prevent running two instances simultaneously — second launch shows a warning dialog and exits immediately; stale locks from crashes are auto-cleared by Qt
- **HTML game support**: `.game` file loader now detects HTML games by inspecting the first 512 bytes for `<!doctype html` or `<html`; HTML games open in the system default browser via `webbrowser.open(file://...)`; Python games continue to run via `QProcess` as before
- **Game launcher — redesigned layout**: centered launch screen with ASCII title (figlet `ansi_shadow`), type badge (`HTML` / `Python`), last-run timestamp, status indicator (● dot changes colour: grey=ready, green=running, red=error), `▶ Run Game` / `■ Stop` / `↺ Restart` buttons (Stop and Restart shown only while running), collapsible logs panel (stdout + stderr via `QProcess` signals), last-run saved to `app_config.json`
- **psview — full analysis saved**: removed 800-character truncation; full model output now stored in `terminal_history.db`
- **psview — Findings marker**: model is prompted to append `Findings = true` or `Findings = false` on the last line; marker is detected (regex, case-insensitive, handles `=`/`:` and `true/yes/1/false/no/0`), stripped from saved output, and used to decide tagging — entry tagged `screenshot` only when `Findings = true`; images with no findings are saved untagged
- **psview — removed `--next` flag**: `psview --next` removed; use `psnext` directly for next-command suggestions
- **pshistory `--categories` — screenshot category**: `screenshot` category added to `tool_categories.json` with label `"Screenshot with findings"` — visible in `pshistory --categories` output; entries tagged automatically by `psview` when the model reports findings
- **psreport `--deep` — token estimate before confirm**: prompt is now built before the `Continue? [y/n]` prompt so the user sees estimated token count (`~chars/4`), model context window (from `context_tokens` profile override or `model_ctx_registry.json`), percentage used if prompt fits, or an EXCEEDS warning with how many chunks the prompt would require; added `_get_ctx_window(profile, base_dir)` helper to `psai.py`
- **psreport — confirm in all modes**: token estimate + context window check (previously only in `--deep`) now shown in every psreport mode including standard and `--notes` — `_confirm_send()` helper reused across all paths
- **psreport — commands-only prompt**: terminal output no longer sent to LLM in standard mode — each entry is formatted as `[ID] $ cmd [ok/exit N]  → findings` (~60 chars) instead of the previous cmd + raw output block; reduces prompt size 10–16× and eliminates risk of prompt injection from tool output; full outputs remain available for evidence injection via placeholders
- **psreport — removed `--deep` and `--full` flags**: both flags removed; single standard mode with intel header + deduplicated filtered commands is sufficient; `--notes` mode retained
- **psreport `-l/--light`**: new flag — limits history to last 40 commands (`_TERMINAL_HIST_LIMIT`); default (no flag) sends full filtered history with no entry cap; `[COMMANDS EXECUTED]` header shows `all N filtered` vs `last N of total`; `_confirm_send` mode label reflects which mode is active
- **psreport `-C/--chunked`**: new chunked mode for large histories or small context models (Ollama 8K-32K); two-phase pipeline — (1) one silent extraction LLM call per active phase (`recon`, `web`, `exploit`, `privesc`, etc.) producing structured JSON `{vulnerabilities, credentials, flags, command_ids}`, (2) one synthesis call with intel header + compact JSON summaries → full report with `<!-- PSEVIDENCE: cmd:ID -->` markers; synthesis prompt is always small (~2K-5K tokens) regardless of history size; extraction falls back to a safe JSON skeleton on parse errors so the pipeline never aborts; `_resolve_placeholders()` runs unchanged on synthesis output; pre-flight confirm shows phase breakdown and total API call count; `--verbose` applies to synthesis call only
- **psreport `--chunked` — auto-split per phase**: when a phase extraction prompt exceeds 75% of the model context window, entries are automatically split into sub-chunks that fit, each gets its own extraction call, results merged via `_merge_phase_summaries()` (dedup by `json.dumps` fingerprint); new helpers: `_build_extraction_prompt()`, `_parse_extraction_json()`, `_merge_phase_summaries()`; pre-flight confirm shows context window size and auto-split notice; API call count shown as "(min)" since splits may add extra calls
- **psreport — findings → source command in intel header** (pomysł 1): credentials, users, hashes, flags and CVEs in `[FINDINGS]` now show `from: [cmd:ID] $ cmd` annotation linking each finding to the command that discovered it — correlated subquery joins `findings` with `commands` via `command_id` FK
- **psreport — commands annotated with findings** (pomysł 2): `[COMMANDS EXECUTED]` section now marks commands that produced findings — format `[ID] $ cmd [ok]  → credential:admin:password | hash:...` so the LLM can immediately see which commands found something significant; only the top 3 findings per command shown; commands with no findings show exit status only
- **psreport — `cmd:ID` direct placeholder resolution** (pomysł 3): `<!-- PSEVIDENCE: cmd:47 -->` resolves directly by row ID (`snapshot_by_id` dict, O(1)) with 100% accuracy — bypasses token search; LLM is instructed to use this format (preferred) over keyword search when a specific command ID is known; `[ID]` prefix in the command list gives the model the IDs it needs
- **Output parser — extended tool coverage**: added 8 new tool parsers — `john` (cracked password lines), `hashcat` (status:cracked + hash:plain pairs), `enum4linux`/`enum4linux-ng` (SMB share enumeration), `smbmap` (share permissions), `sqlmap` (injection point + DBMS detection), `evil-winrm` (shell session target extraction), `wpscan` (WordPress version, vulnerable plugins, user enumeration); `NXC Pwn3d!` marker detection added to existing `netexec`/`crackmapexec` parser — appends `(Pwn3d!)` to credential value and notes
- **psreport `-N/--nano` → renamed `-C/--chunked`**: nano mode renamed to `--chunked`; section-by-section report generation without a synthesis call; two-phase pipeline: (1) per-phase extraction (one JSON call per active phase), (2) seven sequential section calls with carry-forward coherence context; Executive Summary generated last, placed first in assembled report; prompt caps scale linearly with `ctx_k` so any context window is utilized; `psreport -C` auto-detects ctx_window from profile, `psreport -C 16` forces 16K per section call
- **psreport `-L/--limit N`**: replaces `--light`; limits history to last N commands **per phase category** (recon/scan/exploit/…) instead of a flat total — ensures balanced coverage across the whole engagement; works with all modes (`default`, `--chunked`, `--notes`); confirm prompt shows `last N/phase → M total`
- **psfix `--fit`**: new flag for context-aware prompt trimming — works in both fix mode and `-a` analyze mode; fix mode: trims failed command output to 75% of ctx_window using head (60%) + tail (40%) strategy with `[... N chars omitted ...]` marker so model sees both banner/config and final error; analyze mode: fill-down allocation across 3 priority areas — Area 1 (failed output) ≤50% of data budget, Area 2 (recent history with output) ≤30%, Area 3 (broad cmd-only history) gets remaining tokens; per-entry output cap for recent history scales with area2 budget; falls back to defaults when ctx_window unknown; shows budget breakdown on stderr before querying
- **psnext `--fit`**: new flag for context-aware recent session output cap — measures tokens consumed by structured layers (attack surface, findings, phase coverage) first, then divides remaining 75% ctx_window budget evenly across recent session entries to compute a dynamic per-entry output cap; large models automatically get more output per entry, small models get less; falls back to hardcoded 400 chars when ctx_window unknown

### Changed

- **install.sh — Docker components off by default**: in the interactive whiptail checklist, Docker, Open WebUI and WebMap are moved to the bottom of the list and now default to unchecked (`OFF`) — they are the heaviest, most optional components (~6.6 GB combined); `embedmodel` moved above them and stays checked; selecting Open WebUI or WebMap still auto-enables Docker; the `--all` non-interactive mode is unchanged (still installs everything)
- **psnmap — WebMap Export mutually exclusive with External Terminal**: in the psnmap loader, checking "External Terminal" now clears and disables the "WebMap Export" checkbox (and re-enables it when unchecked) — WebMap Export can't run through an external terminal; the greyed-out state is theme-driven (new `QCheckBox:disabled` / `::indicator:disabled` rules using `text_disabled`), so it follows View → Change Theme instead of a hardcoded color
- **File tree — folders-first natural sort**: the module tree now lists directories before files (like professional IDEs), each group natural-sorted so `file2` comes before `file10` and casing is ignored; `get_ordered_entries` switched to `os.scandir` (cheap `is_dir`, no extra `stat`) and is now reused by the recursive and usermodules paths, replacing the duplicated inline sorts so ordering is consistent at every level
- **AI Settings — "LLM web chat cmd" setting**: new editable row directly under "LLM CLI path" holding the web chat (Open WebUI) launch command; defaults to the built-in docker command, saved under `llama.llm_web_chat_cmd` like the other settings, and used by the AI chat panel's web mode (falling back to the default when cleared). The launch command is no longer hardcoded in the panel — it now reads this setting fresh each time web mode is selected
- **AI Settings — larger Edit popups**: the "Edit value" popup (LLM CLI path, LLM web chat cmd, Agent run command) now uses a multi-line `QPlainTextEdit` (min 560×140, soft word-wrap) instead of a cramped single line, so long values like the docker command are fully visible; the value is still stored as one logical line (hard line breaks neutralized, internal spaces preserved)
- **AI chat — web session Info window & container cleanup**: launching a web interface (e.g. Open WebUI) now opens the Info window automatically once the URL is confirmed, exactly as clicking ℹ would; clicking **stop** first shuts the web engine down and returns the tab to its default view, then re-opens the Info window with the launch console still visible. When the launched command was a genuine `docker run --name X`, stop also runs `sudo docker rm -f X` in that console to stop and remove the container so it frees its RAM — the name is parsed from the actual launch command (handles `sudo`, any flag order, and `--name`/`--name=`), and for any non-docker command (or `docker run` without `--name`) no cleanup command is sent

### Fixed

- **Unknown-model context window shown inconsistently, now provider-tiered**: when a model wasn't in `model_ctx_registry.json` (and its provider section had no `default`), the Profiles → Behavior dialog showed one value while the active-profile tooltip and the live CTX bar showed another. All display paths now share a single **provider-tiered** fallback (`Controller._fallback_ctx_window`, mirrored by the Behavior dialog and the tooltip's defensive branch), so the same value appears everywhere for an unknown model: **ollama → 4 k**, self-hosted local runtimes (**llamacpp, LM Studio, Jan, koboldcpp**) → **32 k** (they typically run smaller models with limited context), and every **cloud provider → 200 k**. Providers with an explicit registry value (e.g. Anthropic 200 000) are unaffected; the resolution order is unchanged (user override → registry model match → registry provider default → this fallback)
- **Opening archive/database/document files crashed the loader with `KeyError`**: extensions mapped to a distinct tree icon but no dedicated loader — archives (`zip`, `7z`, `tar`), databases (`db`, `sqlite`, `sqlite3`) and documents (`doc`, `docm`, `docx`, `odt`, `rtf`) — resolved to loader classes (`Archive_file`/`Database_file`/`Document_file`) that were never registered in `FILE_LOADERS`, so opening one raised `KeyError` and showed an "❌ Error loading file" tab. The loader lookup now falls back to the generic `Unsupported_file` viewer when a class is missing (logged at INFO, not as an error), so these files open gracefully. The distinct tree icons are preserved (icon and loader are resolved independently), and a real loader added later takes over automatically once registered — no mapping change needed
- **AI chat (run mode) — system prompt / fast answers sent an invalid flag**: the side-panel Ollama run command was built with `--system "…"` for a custom system prompt or "Fast answers", but `ollama run` has no `--system` flag, so the session failed with `Error: unknown flag: --system`. The system prompt is now baked into a throwaway model at launch: a temp `Modelfile` (`FROM <model>` + `SYSTEM """…"""`) is written to a tmpdir and the command becomes `ollama create purrsh-chat-<pid>-<rand> -f … && ollama run purrsh-chat-…`, so the prompt applies regardless of how long the model takes to load (no interactive-timing race). The temp model + tmpdir are removed on **stop** (after the run process is torn down), and orphaned `purrsh-chat-<pid>-*` models left by a crash are swept on the next baked launch (skipping any whose owner pid is still alive). Only a genuine `ollama run <profile-model> …` preview is rewritten, so a hand-edited command is left untouched. The ps* tools were already correct (they inject the system prompt as a native API `system` message) and are unchanged
- **AI chat (run mode) — "Hide thinking output" ignored**: the Ollama run command honored "Disable thinking" (`--think=false`) but never applied the profile's `hide_thinking` setting; it now adds Ollama's native `--hidethinking` flag (model still reasons, output is suppressed)
- **AI Settings → Behavior — "Custom parameters" left "Hide thinking output" checked**: enabling the advanced "Custom parameters" JSON now also unchecks "Hide thinking output" (it already cleared "Disable thinking", "Fast answers" and "Temperature") — custom_params is meant to be the sole override when active
- **AI chat — Info button blinked and changed color**: in web mode the ℹ button blinked yellow/grey while polling the container port after launch; removed the blink machinery entirely (timers, blink styles, socket port-poll) so the button keeps its theme styling — the Info window is now shown automatically instead (on launch and on stop)
- **pshistory `--clear` didn't reclaim disk space**: after `pshistory --clear` (and the "Clear terminal history on exit" path) the `terminal_history.db` / `.db-wal` files stayed the same size — `DELETE` is only a logical delete, so SQLite keeps the freed pages in the main file and appends the delete transaction to the WAL. `cmd_clear` now runs `PRAGMA wal_checkpoint(TRUNCATE)` + `VACUUM` after committing (best-effort, wrapped in `try/except` so a concurrent app write returning `SQLITE_BUSY` never fails the command), and `TerminalHistoryDB.clear()` runs `VACUUM` (the WAL is already truncated by the `close()` that follows). Verified: a 12.5 MB DB shrank to ~86 KB with a live app connection held open. Also aligned `cmd_clear` with `clear()` — it now deletes `pstool_commands` too (previously it left the ps* helper rows behind)
- **Desktop identity — process/taskbar showed "main.py"**: the app never declared an application identity, so Qt derived WM_CLASS/app_id from `argv[0]` ("main.py") and the installed `.desktop` had no `StartupWMClass` to map the window back to it — some desktop environments showed "main.py" instead of "PurrSh3ll" in the process/task list (the icon was already correct, coming straight from `setWindowIcon`); `main.py` now calls `setApplicationName("PurrSh3ll")` + `setDesktopFileName("purrsh3ll")`, and the installer's `.desktop` gains `StartupWMClass=purrsh3ll` so X11/Wayland match the window to it for the correct name + icon (existing installs need the `.desktop` regenerated via `install.sh`)
- **File tree — search hid matches inside collapsed folders**: typing in the tree filter revealed the containing folder but not the matched file inside it, because `filter_tree` only toggled `setHidden` and never expanded parents; it now expands folders that contain a match, snapshots the expansion state when a search begins and restores it exactly when the search is cleared, and blocks tree signals during the pass so the programmatic expand/collapse doesn't pollute the persistent `expanded_modules` state
- **File tree — file vanished from view on failed move**: dragging a file into a folder without write permission removed it from the tree even though the move failed (the file was still on disk, reappearing only after another action forced a rebuild); `dropEvent` called `event.accept()` unconditionally, so with the default `MoveAction` Qt removed the source row. Now the tree accepts only on a successful `shutil.move` and calls `event.ignore()` on failure; it also pre-checks `os.W_OK` on the destination for a clearer message and to skip the doomed move attempt
- **uninstall.sh — failed on root-owned WebMap files**: removing the app folder aborted with `rm: cannot remove …/webmap/report.xml: Permission denied` because WebMap XML is written as root (Docker bind mount / earlier sudo nmap scans) and `set -e` stopped the run; the uninstaller now tries an unprivileged `rm -rf` first and escalates to `sudo rm -rf` only when it fails, guarded by a check that refuses to remove an empty / `/` / `$HOME` path
- **Terminal hint overlay lingering over output**: the one-shot `# Type pshelp to see available tools` hint only dismissed on a key press, so a command run from the app (e.g. Help → Health Check) left the hint overlaid on the output — now also dismissed when a command is sent into the terminal programmatically (Health Check, snippets, chat, …) by wrapping the console's `sendText`; deliberately not tied to `receivedData`, so resizing the terminal/window or clicking a menu no longer dismisses it prematurely
- **psnmap — WebMap Export failed with sudo scans**: `sudo xmlwrap nmap …` failed with `sudo: xmlwrap: command not found` because `xmlwrap` is a zsh function, not an executable, and `sudo` resolves only binaries on PATH; the command is now generated as `xmlwrap sudo nmap …` — the wrapper runs as the user and applies `sudo` only to the nmap call (raw-socket scans like `-sS`/`-sU` need root); the zsh function strips a leading `sudo` into `$USE_SUDO`, re-applies it to each nmap invocation, and `chown`s the auto-generated XML back to the invoking user (sudo credentials still cached, no second prompt) so the app can read/clean it
- **psnmap — WebMap page failed to load on any non-8000 Visualizer Port**: the container was mapped to the configured port (`-p <port>:8000`) but the embedded web view URL was hardcoded to `http://127.0.0.1:8000/`, so any port other than 8000 loaded nothing (`ERR_CONNECTION_REFUSED`) even though the container was running (`docker ps` showed e.g. `0.0.0.0:8001->8000/tcp`); the view now builds the URL from the configured port (`http://127.0.0.1:<port>/`) so host mapping and preview URL always agree
- **psnmap — "Port Mismatch" popup after changing the Visualizer Port**: Docker cannot change a container's port mapping after creation, and the app only created the `webmap` container when none existed — so changing the port while an old container survived surfaced a blocking `⚠️ Container 'webmap' port mismatch` critical dialog and refused to continue; the mismatch path now offers a confirmation dialog ("remove the old container and recreate it on port X?") that runs `docker rm -f webmap` + recreates on the new port when accepted, and keeps the previous guard behaviour (does nothing) when declined; the `docker run` block was extracted into a shared `_create_webmap_container()` helper used by both the first-create and recreate paths
- **Memory — CSV table registry not pruned on tab close**: `tracked_tables` (class-level list populated by the CSV loader) was only pruned on a theme change, so opening and closing many CSV files left the view wrappers accumulating — now pruned on every tab close alongside `tracked_combos` in `_prune_class_registries`; the CSV loader's `cleanup()` also unregisters its own `QTableView` from `tracked_tables` and detaches the model (`setModel(None)`) so all row data is released immediately rather than waiting for the widget's C++ deletion
- **Hide thinking — Google/Gemini models**: "Hide thinking output" checkbox in Behavior now works correctly for Gemini models in all ps* tools (`psfix`, `psnext`, `psreport`, `psview`) — `hide_thinking` was not being read from the profile or passed to `_run_llm`, so thinking always appeared in gray regardless of the checkbox state; fixed by reading `hide_thinking` from the active profile and forwarding it on every `_run_llm` call in all four tools
- **Hide thinking — pstldr**: `pstldr` read `disable_thinking` from the profile but never `hide_thinking`, and called `_run_llm` without it, so with "Hide thinking output" checked the reasoning still streamed as gray text instead of the animated spinner; fixed by reading `hide_thinking` and forwarding it to `_run_llm`, matching the other psai tools
- **Hide thinking — psrag**: `psrag` has its own separate streaming engine (CLI-based ollama plus its own OpenAI-compat/Anthropic runners) and never implemented `hide_thinking`, so reasoning models always showed their thinking as plain text; ported psai's thinking handling into all three runners while keeping psrag's own `disable_thinking` logic (Groq `/no_think`, Gemini/OpenRouter `reasoning_effort`, Anthropic `thinking:disabled`) — OpenAI-compat reads the `reasoning` delta with a `<thought>…</thought>` content-stream fallback, Anthropic handles `thinking` content blocks, and the ollama CLI path adds `--hidethinking` (guarded by a one-time capability probe so older ollama falls back gracefully); all three animate a spinner while thinking is hidden. With the box unchecked, thinking now renders like the other psai tools (reasoning surfaced in gray, `<thought>` tags stripped) rather than psrag's prior raw passthrough
- **upsert_target / upsert_port**: `sqlite3.OperationalError: ON CONFLICT clause does not match any PRIMARY KEY or UNIQUE constraint` on databases created before the sessions era was removed — replaced `ON CONFLICT(col) DO UPDATE` syntax with explicit SELECT + INSERT/UPDATE pattern that works with any schema version; targets and ports were silently not being saved
- **psrag**: `Knowledge base is empty` error when only terminal snippets existed — empty check in `psrag_query.py` only queried the `rag_kb` ChromaDB collection; now also checks the `memory` collection before exiting with an error
- **Agent Configuration / AI Settings labels**: "agent role:" → "Agent role:", "Skills & agents:" capitalized consistently across the Agent Configuration dialog and AI Settings panel
- **pshistory**: exit code `0` shown as `?` — `exit_code or '?'` treated `0` as falsy; fixed to `str(ec) if ec is not None else '?'`
- **pshistory `--clear`**: AUTOINCREMENT counter not reset after clearing history — added `DELETE FROM sqlite_sequence` so IDs start from 1 after a clear
- **Terminal history DB — WAL growth**: the `-wal` file grew every session and never shrank because the app held one long-lived connection and never checkpointed on shutdown; `TerminalHistoryDB.close()` now runs `PRAGMA wal_checkpoint(TRUNCATE)` before closing (called from `_cleanup_on_close`), and `PRAGMA journal_size_limit = 8 MB` caps the WAL during a running session
- **Fresh install — false "PurrSh3ll is already running"**: on a freshly cloned/installed machine `appdata/logs/` did not exist (gitignored), so `QLockFile` could not create `app.lock`, file logging was silently disabled and the health-check reported "logs writable" degraded; `setup_logging()` now creates the log directory first, before the lock file and any logging
- **psfix `-a` — cross-terminal history**: analyze mode was scoped to the invoking terminal and did not pull history/output from other terminals; `_load_recent_history` now reads across all terminals in `-a`, while the last failing command to fix stays scoped to the invoking terminal (`_last_terminal_entry`)

### Removed

- **terminal_history.jsonl — fully removed**: dual-write to JSONL eliminated from `terminal_tabs.py`; `main_window.py` no longer deletes the JSONL file on exit (only SQLite DB is cleared); `terminal_history.jsonl` file deleted; SQLite (`terminal_history.db`) is now the sole storage backend for terminal history
- **terminal-history-reader SKILL.md**: deleted from both `claude-code-pentest` and `awesome-claude-skills-security` skill sets — no longer applicable without JSONL
- **Agent CLAUDE.md files — jsonl references removed**: all four agent modes (`pentest`, `ctf`, `ctf_skills`, `pentest_skills`) updated — `tail terminal_history.jsonl` instructions replaced with `pshistory` commands (`pshistory -n 30`, `--targets`, `--findings`, `-t <phase>`, `-q <keyword>`, `--stats`); `user_guide.md` updated to reflect SQLite storage
- **default skills folder**: removed `appdata/agent_modes/skills/default/` and its `terminal-history-reader` SKILL.md — terminal history awareness is now a behavioural instruction baked directly into each agent CLAUDE.md file
- **Skills Usage sections**: removed `## Skills Usage` sections from `ctf/CLAUDE.md` and `pentest/CLAUDE.md` — referenced `/mnt/skills/` paths that do not apply to PurrSh3ll; skill routing belongs in `ctf_skills` and `pentest_skills`
- **pshistory `--db`**: removed `--db /path/to.db` flag — DB path is always fixed to `appdata/logs/terminal_history.db`; reduces CLI surface

---

## [1.1.0] — 2026-06-12

### Added

- **ps* tools**: `-m` / `--model` flag replaced by `-p` / `--profile` across all tools (`psai`, `pscmd`, `psfix`, `psnext`, `psrag`, `psreport`, `pstldr`, `psview`) — better reflects that the argument is a profile name, not a model name
- **ps* tools**: short flag aliases added for all long-only flags where no conflicts exist — `-H`/`--host`, `-r`/`--rag`, `-n`/`--top-n`, `-s`/`--show-sources` (psrag), `-e`/`--explain`, `-a`/`--analyze` (psfix), `-t`/`--target`, `-r`/`--rag` (psnext), `-d`/`--deep`, `-v`/`--verbose`, `-f`/`--format`, `-t`/`--target`, `-T`/`--title` (psreport), `-c`/`--cmd`, `-N`/`--next` (psview), `-c`/`--clear` (pschat); flags without natural short forms or with conflicts remain long-only (`--new`, `--history`, `--full`, `--head`, `--tail`, `--paste-mode`)
- **README**: added note that paid API providers (Anthropic, OpenAI) have not been end-to-end tested with real API keys
- **pschat**: global chat history — session is now shared across all profiles (`global.json`); switching models mid-conversation no longer resets context; history format is plain `{"role", "content"}` text pairs, compatible with all providers
- **pschat `--history`**: each assistant message now stores and displays the model name that actually responded — `model` field saved per assistant entry; old entries without the field fall back to the currently active model
- **AI Settings → ps* tools**: "Chat history (messages)" spinbox — configures how many past user prompts are kept in context (default 20, range 1–999); "Default" button resets to 20; stored as `chat_max_history` in config, applied as `value × 2` messages internally
- **pstldr**: `--head [N]` flag — send only the first N characters to the model (default 4000); `--tail [N]` flag — send only the last N characters (default 4000, useful for logs); both accept an optional character count; no flag sends the full content as before
- **AI Settings → RAG tab**: Terminal snippets list now supports single-item deletion — click a snippet to select it, then press "Delete selected" (with confirmation dialog) to remove it from ChromaDB permanently
- **AI Settings → RAG tab**: "Delete all snippets" button added next to "Delete selected" — removes all terminal snippets from the memory collection with a confirmation dialog
- **AI Settings → RAG tab**: AI Settings dialog is now non-modal — main window remains accessible and interactive while AI Settings is open
- **RAG index status label**: shows `⟳ Starting indexing…` immediately when indexing begins (both auto-index and manual Refresh index) — `QApplication.processEvents()` forces repaint before the worker thread starts so the label is visible before any potential freeze
- **Terminal → Save selection to RAG memory**: RAG index status label near the voice button now shows `⟳ Saving to memory…` immediately on click, then `✔ Saved to memory` or `✖ Memory save failed` for 3 seconds after completion
- **Terminal snippets preview**: increased from 30 to 40 characters
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

### Removed

- **tiktoken**: removed from About/licenses dialog and uninstalled from venv — no longer used anywhere in the project
- **Behavior dialog — Context limit**: spinbox, reset button, info button and Ollama auto-detect thread removed — context limit is now read-only info derived from the model registry
- **ps* tools**: tiktoken dependency and token-based history trimming removed from `psai`, `psfix`, `psnext`, `psview`, `psrag_query` — history loading replaced with last-40-entries count-based approach
- **psreport**: map-reduce chunking in deep mode removed — all entries sent in a single request
- **pstldr**: `--tail` flag removed — file content sent to the model in full without truncation

### Fixed

- **pschat**: HTTP 400 from Groq (and other strict providers) caused by `model` field in assistant messages — `msgs_to_send` now strips all non-API fields (`model`, any future extras) before sending; `model` is retained in the session file for `--history` display only
- **AI Settings → RAG tab**: checking an excluded file when "Enable automatic indexing" is off now sets the file status to `pending` instead of immediately triggering re-indexing; indexing will happen on the next manual "Refresh index" or when auto-indexing is re-enabled
- **AI Settings → RAG tab**: RAG index status label and local dialog status now both visible immediately on Refresh index click — `QApplication.processEvents()` added before `worker.start()` in both `menu_builder.py` and `controller.py`
- **Installer**: Ollama install retries up to 3 times on transient HTTP errors (504, 503, 502)
- **Installer**: `sudo -v` refresh before each Docker image pull to prevent sudo password prompt mid-output
- **Installer**: `docker-cli` added to apt install — provides `/usr/bin/docker` binary on Kali (previously only daemon was installed)
- **Installer**: `DOCKER_OK` now set when Docker is already installed on re-run
- **Installer**: `dpkg -s docker.io` used as fallback check when `command -v docker` misses freshly installed binary
- **Installer**: `OLLAMA_OK` and `AICHAT_OK` flags set when tools already installed — fixes summary showing `✗ failed` for pre-installed components
- **Installer**: Open WebUI and WebMap Docker images skipped if already present locally (`docker image inspect`) — avoids re-pull on every re-run
- **Installer**: Docker presence detected independently of checklist selection — Open WebUI/WebMap pulls now work when Docker is pre-installed but not selected
- **Installer**: embedding model download skipped if `.onnx` files already present in cache directory
- **Installer**: `git pull --ff-only` failure is non-fatal — shows warning and continues instead of aborting
- **Installer**: incomplete QTermWidget wheel cache removed automatically (< 100 KB) and re-downloaded
- **Installer**: aichat install wrapped in error handling — shows `warn` on failure instead of crashing with `set -e`
- **Installer**: duplicate info line before embedding model spinner removed
- **Installer**: Ollama size corrected to `~1.5 GB`, Open WebUI to `~4.8 GB`, WebMap to `~1.5 GB`
- **Installer**: timer loop shows download percentage during Ollama install (`downloading: 42.3% (30s elapsed)`)
- **Installer**: Docker image pulls show layer progress with total count (`8/47 layers done`) and download bytes per active layer
- **Installer**: apt progress now visible during system dependencies install (`Get:`, `Unpacking`, `Setting up`)
- **Installer**: pip package names visible during Python packages install (`Collecting`, `Downloading`, `Successfully installed`)
- **Installer**: interactive whiptail checklist installer replacing `install.sh` and `install_full.sh` — optional components selectable per run (Ollama, aichat, Docker, Open WebUI, WebMap, Voice, AI Skills, embedding model)
- **Installer**: optional multilingual embedding model download (`paraphrase-multilingual-MiniLM-L12-v2`, ~220 MB) selectable during install; downloaded once and reused on every RAG use
- **psrag**: `_build_prompt(query, chunks)` now called before `_run_llm` — fixes `UnboundLocalError` on every query
- **psview**: multimodal messages normalized to Ollama native format before sending — extracts base64 images into `images` array and joins text parts into plain string; fixes HTTP 400 on Ollama vision models
- **Session restore**: files now reopen with the correct loader — `.purr` files (psnmap, psc2) and all other typed loaders restore using the saved `class_name` instead of falling back to `Text_file`; `session.json` format updated to `[{path, class_name, icon_token}]` with full backwards-compatibility for old plain-string entries
- **Session restore**: tab icons now restored correctly — `icon_token` saved per-tab and reused on restore; previously all restored tabs showed the default file icon regardless of extension
- **Script loader (.py)**: docs and help tabs now auto-refresh when the file is modified on disk — `QFileSystemWatcher` monitors the open file and calls `update_docs()` / `update_help()` automatically; handles atomic-save editors (PyCharm, VS Code) by re-adding the path to the watcher after each rename-based save
- **Behavior dialog**: clicking a checkbox (Disable thinking, Hide thinking, Fast answers) while Custom parameters is checked now checks the clicked option and automatically unchecks Custom parameters; previously those checkboxes were disabled and could not be interacted with
- **Behavior dialog**: Custom parameters text field resizes with the dialog window — replaced `setFixedHeight` with `setMinimumHeight` and added `stretch=1`; dialog now has a visible resize grip
- **Behavior dialog**: scrollbar click inside the Custom parameters field no longer clears the placeholder text — replaced `QTextEdit` + manual `focusInEvent`/`focusOutEvent` with `QPlainTextEdit` and native `setPlaceholderText()`
- **Behavior dialog — Context limit**: spinbox stepped from 0 instead of the default value (16 000) — fixed by subclassing `QSpinBox` and overriding `stepBy()` to start from `_ctx_default`
- **Behavior dialog — Context limit**: context window number displayed as `131,072` — now formatted with space separator: `131 072`
- **AI Settings → RAG tab**: Rerank model combobox scrollbar color now matches the active theme — converted to `_ScrollableComboBox` with themed scrollbar stylesheet; both RAG comboboxes now update their scrollbar style on every theme change
- **psnmap**: added tooltips to the options button (⚙ `Configure scan profiles and psnmap options`) and the WebMap button (🌐 `Start WebMap container`)
- **psai**: thinking text color changed from dim (`\033[2m`) to gray (`\033[90m`) — consistent with info lines; animated braille spinner shown while thinking is hidden
- **psai**: Hide thinking — display-only suppression replacing the unreliable API-level `disable_thinking` for non-Ollama providers; Ollama retains both checkboxes (Disable thinking + Hide thinking output)
- **psai ask / chat**: `KeyboardInterrupt` (Ctrl+C) now exits cleanly with code 130 and resets ANSI dim style if interrupted during thinking output — no traceback printed; all three streaming paths covered (`_stream_ollama_native`, `_stream_openai_compat`, `_stream_anthropic`) plus top-level `main()` handler
- **psai ask / chat**: thinking process was always disabled — `think` flag must be at the **top level** of the request body, not inside `options`; fixed for Ollama native endpoint
- **psai ask / chat**: `disable_thinking` in Behavior now correctly suppresses thinking output — switched Ollama calls to native `/api/chat` endpoint (`_stream_ollama_native`) which correctly honors `think: false`; `/v1/chat/completions` ignored the flag for this model family
- **psai chat**: `delta.get("reasoning")` used instead of `delta.get("thinking")` — Ollama's OpenAI-compat stream uses field name `"reasoning"` for thinking tokens
- **Ollama**: `"think"` field no longer sent when `disable_thinking` is off — omitting it lets thinking-capable models use their default behavior, and prevents HTTP 400 errors on models that don't support thinking
- **psfix**: system info (`System: Linux …`) added to `--explain` and default fix mode prompts — was only present in `--analyze` mode
- **psopen**: files now open in the correct viewer based on extension (`.md` → Markdown, `.html` → HTML, `.pdf` → PDF viewer, audio/video → media player) — previously all files landed in the unsupported-file fallback due to `mode=null` overriding the `"Default"` parameter; `.py` opens as code viewer (`Python_file`), `.purr` opens as plain text
- **psopen**: rewrote file opening to use OSC escape sequence protocol — fixes paths with spaces, eliminates race conditions between terminals
- **psopen**: directories now open silently in the default file manager (`xdg-open`)
- **psopen**: removed `PurrSh3ll opened >>` confirmation text from terminal output
- **psview**: always showed 1 token regardless of image size — `len()` on multimodal content list returned list length instead of character count; fixed by `_estimate_prompt_tokens()` with PIL-based image size detection
- **psrag**: `UnboundLocalError: cannot access local variable 'prompt'` on every query — `_build_prompt()` was defined but never called in `main()`
- **psview + Ollama**: HTTP 400 `cannot unmarshal array into Go struct field ChatRequest.messages.content of type string` — Ollama native `/api/chat` requires `content` as string + `images` as separate list; fixed by normalizing messages in `_stream_ollama_native`
- **Terminal**: `Ctrl+Shift+V` (paste) no longer crashes the application when focus is in a file editor window — `TypeError` from `QScrollArea.parent()` traversal now caught and handled gracefully
- **Terminal**: split view labels corrected — "Split View Left-Right" and "Split View Top-Bottom"
- **Terminal**: zoom (buttons, Ctrl+Scroll, right-click menu) now works correctly in split terminals, including Zoom Reset option
- **Terminal**: commands executed in split terminals are now logged to `terminal_history.jsonl` (visible to `psfix`, `psnext`, `psreport`)
- **Terminal**: Pause Agent Monitoring now also pauses history logging for the split terminal in the same tab
- **Terminal**: `psopen` now opens files from split terminals the same way as the primary terminal
- **Terminal**: split terminal now receives silent variable/alias injection from Observable Panel (own FIFO assigned at creation, cleaned up on unsplit)
- **Terminal**: split terminal right-click menu now includes Find option with theme-aware search bar styling
- **Terminal**: reduced visual artifacts after search bar toggle and split/unsplit — improved repaint logic using `setTerminalFont` to trigger full character grid recalculation (known issue: artifacts may still appear in some cases)
- **Terminal right-click context menu**: colors did not match current theme — `menu.setStyleSheet(menu_stylesheet)` applied to all three QMenu instances (main terminal, split terminal, tab bar) and their `_scheme_menu` submenus
- **Syntax highlighting**: all 19 hand-written regex highlighters replaced by a single `PygmentsHighlighter` backed by the Pygments library — 500+ languages supported, edge-cases handled by the community, colors still driven by `qss_QPainter` theme
- **Syntax highlighting**: files with unknown extensions (`.yaml`, `.toml`, `.css`, `.rs`, `.ts`, `.env`, `Dockerfile`, `Makefile` etc.) now auto-detect language via `guess_lexer_for_filename()` and receive syntax highlighting automatically
- **File icons**: unknown extensions now show a neutral icon instead of "unsupported"; the unsupported icon is reserved for 62 known binary/non-openable formats (video, audio, archives, executables, fonts, 3D assets etc.)
- **HTML viewer**: three view mode buttons (`</>` code, `◫` split, `≡` preview) added before the browser button — split view is the default
- **Snippets**: placeholder dialog is now non-modal — other windows (terminal, tabs) remain accessible while filling in values; all placeholders shown at once in a single form
- **Welcome screen dialog**: colors did not match current theme — fixed by applying `c.dialog_stylesheet` instead of `c.messagebox_stylesheet`
- **Observable Panel**: "Missing Data" warning dialog text color did not match theme — `c.messagebox_stylesheet` now applied before `msg.exec()`
- **Themes**: default theme reset to `default` — was incorrectly committed as `Red Team`
- **Markdown preview**: zoom (buttons + Ctrl+Scroll) now scales images alongside text; images fit the preview width automatically and never upscale beyond natural size
- **Markdown preview**: content no longer cut off on file open without requiring a splitter resize; horizontal scrollbar removed to prevent flicker
- **Security**: sudo password no longer stored in GNOME Keyring — now kept in a `bytearray` in RAM for the session duration and securely zeroed at shutdown via `ctypes.memset`; eliminates "Unlock Login Keyring" popup on application exit
- **testfolder**: removed `usermodules/testfolder/` from git tracking — folder is now ignored via `.gitignore` and will no longer appear in the repository; files remain locally
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

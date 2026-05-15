# terminal-history-reader

## Purpose
Read and analyze terminal activity from the current session by parsing `terminal_history.jsonl` located in the working directory. Use this skill when you need to understand what commands were run, what their outputs were, or what is currently happening in the system.

## File format
Each line in `terminal_history.jsonl` is a JSON object:
```json
{"ts": 1700000000, "ts_end": 1700000001, "terminal": "terminal_1", "cmd": "nmap -sV 10.0.0.1", "exit_code": 0, "output": "..."}
```
- `ts` / `ts_end` — Unix timestamps (start / end of command)
- `terminal` — which terminal tab ran the command
- `cmd` — the exact command that was executed
- `exit_code` — 0 = success, non-zero = error
- `output` — full stdout/stderr captured from the terminal

## Important limitation — interactive tools
**Entries are only written to the file after a command fully exits.** This means:
- If the user is currently running an interactive tool (e.g. `msfconsole`, `vim`, `htop`, `gdb`, a reverse shell, a running server), **that session will not appear in the history yet** — it will only be recorded once the user exits that tool.
- The absence of recent entries for a terminal does not mean that terminal is idle; it may have an active interactive session in progress.
- Keep this in mind when assessing system state: the history gives a reliable picture of completed activity, but the current moment may have more going on than what is visible here.

This is a minor caveat — do not let it dominate the analysis. Focus on what the history does show.

## How to use this skill

### Step 1 — always start from the most recent entries
Read from the end of the file first. The file can be large; reading the tail gives the freshest context fastest.

```bash
tail -n 50 terminal_history.jsonl
```

If that is not enough context, expand:
```bash
tail -n 200 terminal_history.jsonl
```

### Step 2 — filter by terminal if needed
If the user mentions a specific terminal tab, filter to that terminal only:
```bash
grep '"terminal": "terminal_2"' terminal_history.jsonl | tail -n 30
```

### Step 3 — filter by time window if needed
To see only recent activity (last 10 minutes), calculate the Unix timestamp cutoff and filter:
```bash
python3 -c "
import json, time
cutoff = int(time.time()) - 600
with open('terminal_history.jsonl') as f:
    lines = f.readlines()
for line in lines[-200:]:
    try:
        e = json.loads(line)
        if e.get('ts', 0) >= cutoff:
            print(f\"[{e['terminal']}] {e['cmd']}\")
            if e.get('output'):
                print(e['output'][:300])
            print()
    except:
        pass
"
```

### Step 4 — look for errors
To quickly surface failed commands:
```bash
python3 -c "
import json
with open('terminal_history.jsonl') as f:
    lines = f.readlines()
for line in lines[-300:]:
    try:
        e = json.loads(line)
        if e.get('exit_code', 0) != 0:
            print(f\"[EXIT {e['exit_code']}] [{e['terminal']}] {e['cmd']}\")
            if e.get('output'):
                print(e['output'][:400])
            print()
    except:
        pass
"
```

## Decision flow
1. User asks what is happening / what was run → **Step 1** (tail recent entries)
2. User asks about a specific terminal → **Step 2** (filter by terminal)
3. User asks about recent activity in a time window → **Step 3** (time filter)
4. User asks what went wrong / errors → **Step 4** (exit_code filter)
5. Need full history → read the whole file with `cat terminal_history.jsonl` (may be large)

## Notes
- Always summarize findings in plain language after reading the file
- Truncate long outputs in your summary to the most relevant parts
- If `terminal_history.jsonl` does not exist, inform the user that no session history is available yet
- Remember: history reflects completed commands only — mention active interactive sessions as a possibility when the picture looks incomplete, but keep it brief

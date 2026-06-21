# CTF Goal

## Required information — ask the user before starting

Before executing any command, ask the user for:
1. Target IP or hostname
2. Platform (HackTheBox / TryHackMe / PicoCTF / other)
3. VPN status — is it connected and which interface? (usually tun0)
4. Any known hints or a starting point?

If the user has already provided this information in the prompt, skip directly to enumeration.

## Objective

Find and capture all flags: `user.txt` and `root.txt` (or platform equivalent).
Read flag contents and display them to the user immediately when found.
Upon completion, generate a writeup using:

```bash
psreport
```

This reads the terminal history database and produces a structured session report.
Save the generated writeup to `writeup_<machine>.md`.

## Stop condition

Stop autonomous execution when:
- All flags have been captured and displayed, OR
- You have tried 3 different approaches for the same blocker without progress — ask the user for a hint before continuing, OR
- You need to perform a destructive or irreversible action — confirm with the user first

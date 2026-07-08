"""Central 'Erase all data' registry and executor.

Single source of truth for every ephemeral / engagement data store the app
collects on disk, so the wipe stays complete as new stores are added. The UI
(Edit → Erase all data…) renders a checkbox per item and calls wipe() with the
selected ids.

Pure stdlib (no PyQt) so it is unit-testable; the optional `controller` argument
lets the executor close live handles (history DB) and reload state after a wipe.

This is an application-level erase — it removes the files/records the app keeps.
It is NOT a forensic disk wipe (SSD wear-levelling, journals, swap and shell
history outside the app are out of scope), and the UI states this plainly.
"""

import glob
import json
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)


class WipeItem:
    """One user-selectable erase category.

    kind:
      "paths"        — delete each entry in `paths` (files, dirs or globs)
      "dynamic_vars" — clear user-defined variables in dynamic_variables.json
      "credentials"  — delete API keys from the OS keyring + api_keys.json
      "docker"       — stop & remove all Docker containers (needs sudo password)
    """
    __slots__ = ("id", "label", "description", "default", "kind", "paths")

    def __init__(self, id, label, description, default, *, kind="paths", paths=None):
        self.id          = id
        self.label       = label
        self.description = description
        self.default     = default
        self.kind        = kind
        self.paths       = paths or []


def build_wipe_items(base_path):
    """Return the ordered list of erasable categories with paths resolved against
    base_path. Defaults: engagement data that simply accumulates is pre-checked;
    things the user authored or needs to keep working (variables, snippets,
    credentials) are left unchecked so wiping them is always a deliberate choice.
    """
    def ap(*p):   return os.path.join(base_path, "appdata", *p)
    def logs(*p): return os.path.join(base_path, "appdata", "logs", *p)

    return [
        WipeItem("history_db", "Command history database", default=True,
                 description="All terminal commands, output and extracted findings, "
                             "targets and ports (terminal_history.db) — includes psnmap "
                             "and .purr runs logged to the shared history.",
                 paths=[logs("terminal_history.db"), logs("terminal_history.db-wal"),
                        logs("terminal_history.db-shm"), logs("testdb")]),

        WipeItem("script_notes", "Script notes (.py / .purr)", default=True,
                 description="Notes attached to individual script files in the side panel "
                             "(scripts_notes/).",
                 paths=[ap("scripts_notes")]),

        WipeItem("notepad", "Side-panel notepad", default=True,
                 description="Free-text notes from the side-panel notepad (psnotes.txt).",
                 paths=[ap("psnotes.txt")]),

        WipeItem("chat_sessions", "AI chat sessions", default=True,
                 description="pschat conversation history — full AI conversations "
                             "(chat_sessions/).",
                 paths=[ap("chat_sessions")]),

        WipeItem("agent_workspace", "Claude Code agent workspace", default=True,
                 description="The hidden Claude Code workspace: agent-created files, the "
                             "copied CLAUDE.md / goal / skills, its .claude state and the "
                             "nested git repo (agent_workspace/).",
                 paths=[ap("agent_workspace")]),

        WipeItem("rag_index", "RAG knowledge-base index", default=True,
                 description="Documents and snippets indexed into the vector database "
                             "(rag/chroma_db, index metadata).",
                 paths=[ap("rag", "chroma_db"), ap("rag", "index_meta.json"),
                        ap("rag", "excluded_files.json")]),

        WipeItem("images", "Analyzed images / screenshots", default=True,
                 description="Images collected or analyzed by psview (images/).",
                 paths=[ap("images")]),

        WipeItem("logs", "Application logs", default=True,
                 description="Diagnostic logs and crumbs: app.log, pstools.log, prompt "
                             "stats and IPC files (logs/).",
                 paths=[logs("app.log*"), logs("pstools.log*"),
                        logs("psai_prompt_stats.json"), logs("psai_tok"),
                        logs("rag_status"), logs(".claude")]),

        WipeItem("system_variables", "Saved system variables", default=False,
                 description="User-defined dynamic variables from the side panel "
                             "(dynamic_variables.json). Built-in variables are kept.",
                 kind="dynamic_vars"),

        WipeItem("snippets", "Saved snippets", default=False,
                 description="Reusable command snippets from the side panel "
                             "(snippets.json).",
                 paths=[ap("snippets.json")]),

        WipeItem("credentials", "API keys (keyring + file)", default=False,
                 description="Stored API keys — OS keyring entries and the plaintext "
                             "fallback (api_keys.json). Provider profiles stay configured; "
                             "you must re-enter keys afterwards.",
                 kind="credentials"),

        WipeItem("docker", "Docker containers (ALL)", default=False,
                 description="Stop and remove ALL Docker containers on this host "
                             "(docker rm -f), including Open WebUI and WebMap. Requires "
                             "the sudo password.",
                 kind="docker"),
    ]


# ── Executor ─────────────────────────────────────────────────────────────────

def _remove_path(pattern):
    """Remove a file, directory or glob pattern. Directories are emptied and
    recreated so the app still finds the (now empty) folder. Returns count removed."""
    matches = glob.glob(pattern)
    if not matches and os.path.lexists(pattern):
        matches = [pattern]
    removed = 0
    for m in matches:
        try:
            if os.path.isdir(m) and not os.path.islink(m):
                shutil.rmtree(m, ignore_errors=True)
                os.makedirs(m, exist_ok=True)   # keep an empty dir in place
            else:
                os.remove(m)
            removed += 1
        except OSError:
            logger.warning("data_wipe: could not remove %s", m, exc_info=True)
    return removed


def _wipe_paths(item):
    total = 0
    for p in item.paths:
        total += _remove_path(p)
    return f"removed {total} item(s)"


def _wipe_dynamic_vars(base_path, controller):
    path = os.path.join(base_path, "appdata", "dynamic_variables.json")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return "no variables file"
    n = len(data.get("user_variables", []))
    data["user_variables"] = []
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    if controller is not None and hasattr(controller, "load_dynamic_variables"):
        try:
            controller.load_dynamic_variables()
        except Exception:
            logger.warning("data_wipe: reload dynamic variables failed", exc_info=True)
    return f"cleared {n} variable(s)"


def _wipe_credentials(base_path):
    detail = []
    # OS keyring — try every profile/key name across both service-name spellings
    names = set()
    for rel in ("api_profiles.json", "api_keys.json"):
        try:
            with open(os.path.join(base_path, "appdata", rel), encoding="utf-8") as f:
                blob = json.load(f)
            if rel == "api_profiles.json":
                names.update(p.get("name", "") for p in blob.get("profiles", []))
            else:
                names.update(blob.keys())
        except Exception:
            pass
    names.discard("")
    deleted = 0
    try:
        import keyring
        for service in ("purrsh3ll", "PurrSh3ll"):
            for name in names:
                try:
                    keyring.delete_password(service, name)
                    deleted += 1
                except Exception:
                    pass  # entry absent for this service/name — expected
        detail.append(f"{deleted} keyring entr{'y' if deleted == 1 else 'ies'}")
    except Exception:
        detail.append("keyring unavailable")
    # Plaintext fallback file
    kf = os.path.join(base_path, "appdata", "api_keys.json")
    if os.path.exists(kf):
        try:
            os.remove(kf)
            detail.append("api_keys.json removed")
        except OSError:
            detail.append("api_keys.json NOT removed")
    return ", ".join(detail)


def _run_sudo(args):
    """Run `sudo -S -- <args>` reading the password from stdin (never argv/shell,
    so it can't leak via `ps aux`). Returns None if no sudo password is cached."""
    pw_buf = _run_sudo.password
    if not pw_buf:
        return None
    pw = bytes(pw_buf).decode("utf-8", "replace")
    return subprocess.run(
        ["sudo", "-S", "--"] + args,
        input=pw + "\n",
        capture_output=True, text=True, timeout=60,
    )


_run_sudo.password = None   # set per-wipe from controller.sudo_password


def _wipe_docker():
    """Stop and force-remove every Docker container on the host. Uses the cached
    sudo password (Docker needs root here). Never raises the password itself."""
    ps = _run_sudo(["docker", "ps", "-aq"])
    if ps is None:
        return "skipped — no sudo password"
    err = (ps.stderr or "").lower()
    if "incorrect password" in err or "sorry, try again" in err:
        return "skipped — incorrect sudo password"
    if ps.returncode != 0:
        if "cannot connect to the docker daemon" in err:
            return "Docker daemon not reachable"
        if "not found" in err or "no such file" in err:
            return "docker not installed"
        return "docker ps failed"
    ids = [x for x in (ps.stdout or "").split() if x]
    if not ids:
        return "no containers"
    rm = _run_sudo(["docker", "rm", "-f"] + ids)
    removed = len([x for x in (rm.stdout or "").split() if x]) if rm else 0
    return f"removed {removed or len(ids)} container(s)"


def wipe(base_path, selected_ids, controller=None):
    """Erase the selected categories. Returns {id: (ok: bool, detail: str)}.

    Closes the live history-DB handle before deleting it (and resets it so the app
    re-opens a fresh empty DB), and reloads dynamic variables after clearing them.
    Every item is isolated — one failure never aborts the rest.
    """
    selected = set(selected_ids)
    report = {}

    # Make the cached sudo password available to the docker step (if selected).
    _run_sudo.password = getattr(controller, "sudo_password", None) if controller else None

    # Close the live history DB before removing its file, then drop the cached
    # handle so the next access re-creates a fresh empty database.
    if "history_db" in selected and controller is not None:
        try:
            db = getattr(controller, "_terminal_history_db", None)
            if db is not None and hasattr(db, "close"):
                db.close()
            if hasattr(controller, "_terminal_history_db"):
                delattr(controller, "_terminal_history_db")
        except Exception:
            logger.warning("data_wipe: closing history DB failed", exc_info=True)

    items = {it.id: it for it in build_wipe_items(base_path)}
    for wid in selected_ids:
        item = items.get(wid)
        if item is None:
            continue
        try:
            if item.kind == "paths":
                detail = _wipe_paths(item)
            elif item.kind == "dynamic_vars":
                detail = _wipe_dynamic_vars(base_path, controller)
            elif item.kind == "credentials":
                detail = _wipe_credentials(base_path)
            elif item.kind == "docker":
                detail = _wipe_docker()
            else:
                detail = "unknown category"
            report[wid] = (True, detail)
        except Exception as e:
            logger.error("data_wipe: category '%s' failed", wid, exc_info=True)
            report[wid] = (False, str(e))

    _run_sudo.password = None   # don't retain the sudo password on the module
    return report

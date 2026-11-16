"""purragent_core.state — extracted from monolithic purragent.py (Phase A refactor)."""

import json
import os

from purragent_core._shared import (FINDINGS_MAX, MEMORY_KINDS)

def _state_path(base_dir: str) -> str:
    return os.path.join(base_dir, "appdata", "purragent_state.json")



def _load_state(base_dir: str) -> dict:
    try:
        with open(_state_path(base_dir), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}



def _save_state(base_dir: str, **updates) -> None:
    """Merge updates into the saved state (keeps other keys intact)."""
    state = _load_state(base_dir)
    state.update(updates)
    try:
        with open(_state_path(base_dir), "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass  # non-fatal: selection just won't persist to next launch



def _load_memories(base_dir: str) -> list:
    mems = _load_state(base_dir).get("memories")
    return mems if isinstance(mems, list) else []



def _add_memory(base_dir: str, text: str, kind: str) -> bool:
    """Store one memory, deduped on text (case-insensitive). Returns True if added."""
    from datetime import datetime, timezone
    text = (text or "").strip()
    if not text:
        return False
    kind = kind if kind in MEMORY_KINDS else "fact"
    mems = _load_memories(base_dir)
    if any((m.get("text") or "").strip().lower() == text.lower() for m in mems):
        return False
    mems.append({"text": text, "kind": kind,
                 "created": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    _save_state(base_dir, memories=mems)
    return True



def _delete_memory(base_dir: str, text: str) -> list:
    """Remove stored memories matching `text` (case-insensitive, either direction, so the
    model can pass the exact text it sees or a distinctive part). Returns removed texts.
    Since the stored memories are injected into context, the model quotes them accurately."""
    q = (text or "").strip().lower()
    if not q:
        return []
    kept, removed = [], []
    for m in _load_memories(base_dir):
        t = (m.get("text") or "").strip()
        tl = t.lower()
        if tl and (tl == q or q in tl or tl in q):
            removed.append(t)
        else:
            kept.append(m)
    if removed:
        _save_state(base_dir, memories=kept)
    return removed



def _memory_block(base_dir: str) -> str:
    """Remembered instructions + facts as a system-prompt block; empty when none."""
    mems = _load_memories(base_dir)
    if not mems:
        return ""
    instr = [m["text"] for m in mems if m.get("kind") == "instruction"]
    facts = [m["text"] for m in mems if m.get("kind") != "instruction"]
    parts = []
    if instr:
        parts.append("USER INSTRUCTIONS (always follow):\n"
                     + "\n".join(f"- {t}" for t in instr))
    if facts:
        parts.append("REMEMBERED (facts the user asked you to keep):\n"
                     + "\n".join(f"- {t}" for t in facts))
    return "\n\n".join(parts)



def _delete_memory_index(base_dir: str, idx: int):
    """Forget the memory at 1-based position `idx` (as shown by /memory). Returns its
    text, or None if out of range."""
    mems = _load_memories(base_dir)
    if idx < 1 or idx > len(mems):
        return None
    removed = mems.pop(idx - 1)
    _save_state(base_dir, memories=mems)
    return removed.get("text")



def _clear_memories(base_dir: str) -> int:
    """Forget everything; returns how many items were cleared."""
    n = len(_load_memories(base_dir))
    _save_state(base_dir, memories=[])
    return n



def _load_findings(base_dir: str) -> list:
    fs = _load_state(base_dir).get("findings")
    return fs if isinstance(fs, list) else []



def _add_finding(base_dir: str, text: str, where: str = "") -> bool:
    """Store one discovered finding, deduped on text (case-insensitive). Keeps the most
    recent FINDINGS_MAX. Returns True if added (False = empty or duplicate)."""
    from datetime import datetime, timezone
    text = (text or "").strip()
    if not text:
        return False
    where = (where or "").strip()
    fs = _load_findings(base_dir)
    if any((f.get("text") or "").strip().lower() == text.lower() for f in fs):
        return False
    fs.append({"text": text, "where": where,
               "created": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    if len(fs) > FINDINGS_MAX:
        fs = fs[-FINDINGS_MAX:]
    _save_state(base_dir, findings=fs)
    return True



def _findings_block(base_dir: str) -> str:
    """Recorded findings as a system-prompt block; empty when none."""
    fs = _load_findings(base_dir)
    if not fs:
        return ""
    lines = []
    for f in fs:
        w = (f.get("where") or "").strip()
        lines.append(f"- [{w}] {f['text']}" if w else f"- {f['text']}")
    return ("FINDINGS (concrete facts you discovered this session — build on them and "
            "include the relevant ones in your final answer):\n" + "\n".join(lines))



def _clear_findings(base_dir: str) -> int:
    """Forget all recorded findings; returns how many were cleared."""
    n = len(_load_findings(base_dir))
    _save_state(base_dir, findings=[])
    return n


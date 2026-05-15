import threading

from PyQt6.QtCore import QThread, pyqtSignal
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class _KBEventHandler(FileSystemEventHandler):
    def __init__(self, callback):
        super().__init__()
        self._callback = callback

    def on_any_event(self, event):
        # React to all file events and to directory deletions/moves
        # (directory created/modified events alone don't mean content changed)
        from watchdog.events import (
            FileCreatedEvent, FileModifiedEvent, FileDeletedEvent, FileMovedEvent,
            DirDeletedEvent, DirMovedEvent,
        )
        if isinstance(event, (
            FileCreatedEvent, FileModifiedEvent, FileDeletedEvent, FileMovedEvent,
            DirDeletedEvent, DirMovedEvent,
        )):
            self._callback()


class RagWatcher(QThread):
    """
    Monitors a knowledge-base directory for file changes and emits
    `changes_detected` after a debounce period with no further events.
    """
    changes_detected = pyqtSignal()

    def __init__(self, kb_path: str, debounce_sec: float = 3.0, parent=None):
        super().__init__(parent)
        self.kb_path     = kb_path
        self.debounce_sec = debounce_sec
        self._observer   = Observer()
        self._lock       = threading.Lock()
        self._timer: threading.Timer | None = None

    # ── watchdog thread callback ──────────────────────────────────────────────
    def _on_fs_event(self):
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self.debounce_sec, self._fire)
            self._timer.daemon = True
            self._timer.start()

    def _fire(self):
        self.changes_detected.emit()

    # ── QThread ───────────────────────────────────────────────────────────────
    def run(self):
        handler = _KBEventHandler(self._on_fs_event)
        self._observer.schedule(handler, self.kb_path, recursive=True)
        self._observer.start()

        while not self.isInterruptionRequested() and self._observer.is_alive():
            self.msleep(250)

        self._observer.stop()
        self._observer.join(timeout=2.0)

    def stop(self):
        self.requestInterruption()
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        self._observer.stop()

import logging
import logging.handlers
import os
import sys
import threading


def install_exception_handlers(base_path: str) -> None:
    """Route uncaught exceptions (main thread + worker threads) to the log file
    and, on the GUI thread, a user-facing dialog — instead of silently crashing
    or dumping a raw traceback. Install once, right after setup_logging().

    critical() also reaches stderr via the stream handler, so startup crashes
    (before any window exists) are still visible on the console.
    """
    log = logging.getLogger("purrsh3ll.crash")
    log_path = os.path.join(base_path, "appdata", "logs", "app.log")
    _prev_hook = sys.excepthook

    def _report(exc_type, exc_value, exc_tb, thread_name=None):
        # Let Ctrl-C behave normally (clean exit, no dialog).
        if issubclass(exc_type, KeyboardInterrupt):
            _prev_hook(exc_type, exc_value, exc_tb)
            return
        where = f" in thread '{thread_name}'" if thread_name else ""
        log.critical("Uncaught exception%s", where, exc_info=(exc_type, exc_value, exc_tb))
        # GUI dialogs are only safe from the main/GUI thread.
        if thread_name is None:
            _show_dialog(exc_type, exc_value, log_path)

    def _hook(exc_type, exc_value, exc_tb):
        _report(exc_type, exc_value, exc_tb)

    def _thread_hook(args):
        _report(args.exc_type, args.exc_value, args.exc_traceback,
                thread_name=getattr(args.thread, "name", None) or "worker")

    sys.excepthook = _hook
    threading.excepthook = _thread_hook


def _show_dialog(exc_type, exc_value, log_path: str) -> None:
    """Show a non-fatal error dialog if a GUI is up. Never raises."""
    try:
        from PyQt6.QtWidgets import QApplication, QMessageBox
        from PyQt6.QtCore import QThread
        app = QApplication.instance()
        if app is None or QThread.currentThread() is not app.thread():
            return  # no GUI yet, or called off the GUI thread → log only
        box = QMessageBox()
        box.setIcon(QMessageBox.Icon.Critical)
        box.setWindowTitle("PurrSh3ll — unexpected error")
        box.setText("An unexpected error occurred. The application will attempt to continue.")
        box.setInformativeText(f"{exc_type.__name__}: {exc_value}")
        box.setDetailedText(f"Full details were saved to:\n{log_path}")
        box.exec()
    except Exception:
        pass  # the crash handler must never crash


def setup_logging(base_path: str, debug: bool = False) -> None:
    log_path = os.path.join(base_path, "appdata", "logs", "app.log")

    # appdata/logs/ is gitignored, so it is absent on a fresh clone/install.
    # setup_logging runs first at startup, so creating it here makes file
    # logging, the health-check "logs writable" probe and the QLockFile
    # single-instance guard (all rooted in this dir) work on first launch.
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
    except OSError:
        pass

    root = logging.getLogger()
    if root.handlers:
        return

    root.setLevel(logging.DEBUG)

    # Wycisz biblioteki które generują masowy szum w logach
    _noisy_libs = [
        "watchdog", "watchdog.observers.inotify_buffer",
        "chromadb", "chromadb.telemetry", "chromadb.api",
        "fastembed", "fastembed.embedding",
        "huggingface_hub", "huggingface_hub.utils",
        "httpx", "httpcore",
        "onnxruntime",
        "PIL",
    ]
    for _lib in _noisy_libs:
        logging.getLogger(_lib).setLevel(logging.ERROR)

    try:
        fh = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=2 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            fmt="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        root.addHandler(fh)
    except OSError:
        pass

    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG if debug else logging.WARNING)
    sh.setFormatter(logging.Formatter("%(levelname)-8s %(name)s — %(message)s"))
    root.addHandler(sh)

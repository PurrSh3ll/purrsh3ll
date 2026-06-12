import logging
import logging.handlers
import os


def setup_logging(base_path: str, debug: bool = False) -> None:
    log_path = os.path.join(base_path, "appdata", "logs", "app.log")

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

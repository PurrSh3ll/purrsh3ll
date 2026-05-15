from PyQt6.QtCore import QThread, pyqtSignal
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path

class PyDeleteHandler(FileSystemEventHandler):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def on_deleted(self, event):
        if event.is_directory:
            return

        path = Path(event.src_path)
        if path.suffix == ".py":
            self.callback(str(path))

class WatchdogThread(QThread):
    file_deleted = pyqtSignal(str)

    def __init__(self, folders: list[str], parent=None):
        super().__init__(parent)
        self.folders = folders
        self._observer = Observer()

    def run(self):
        handler = PyDeleteHandler(self.file_deleted.emit)

        for folder in self.folders:
            self._observer.schedule(handler, folder, recursive=True)

        self._observer.start()
        while not self.isInterruptionRequested() and self._observer.is_alive():
            self.msleep(200)

        self._observer.stop()
        self._observer.join(timeout=2.0)

    def stop(self):
        self.requestInterruption()
        self._observer.stop()

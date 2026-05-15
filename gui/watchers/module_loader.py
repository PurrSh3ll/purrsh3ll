from PyQt6.QtCore import QThread, pyqtSignal
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

class FolderEventHandler(FileSystemEventHandler):
    def __init__(self, signal_callback):
        super().__init__()
        self.signal_callback = signal_callback

    def on_modified(self, event):
        self.signal_callback.emit(f"changed {event.src_path}")

    def on_created(self, event):
        self.signal_callback.emit(f"created {event.src_path}")

    def on_deleted(self, event):
        self.signal_callback.emit(f"deleted {event.src_path}")

class WatcherThread(QThread):
    file_changed = pyqtSignal(str)

    def __init__(self, paths_to_watch):
        super().__init__()
        if isinstance(paths_to_watch, str):
            paths_to_watch = [paths_to_watch]
        self.paths_to_watch = paths_to_watch
        self.observer = Observer()

    def run(self):
        event_handler = FolderEventHandler(self.file_changed)
        for path in self.paths_to_watch:
            self.observer.schedule(event_handler, path, recursive=True)
        self.observer.start()
        try:
            while not self.isInterruptionRequested():
                time.sleep(0.5)
        finally:
            self.observer.stop()
            self.observer.join()


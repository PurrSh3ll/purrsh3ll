from PyQt6.QtCore import QThread, pyqtSignal

from core.rag.indexer import Indexer


class IndexWorker(QThread):
    progress      = pyqtSignal(int, int, str)   # current, total, filename
    finished      = pyqtSignal(str)             # "OK" or "Error: <msg>"
    model_loading = pyqtSignal()                # emitted just before the model loads

    def __init__(self, kb_path: str, base_path: str, model_name: str,
                 allowed_extensions: set | None = None, excluded_rel: set | None = None,
                 parent=None):
        super().__init__(parent)
        self.kb_path            = kb_path
        self.base_path          = base_path
        self.model_name         = model_name
        self.allowed_extensions = allowed_extensions
        self.excluded_rel       = excluded_rel

    def run(self):
        try:
            indexer = Indexer(self.kb_path, self.base_path, self.model_name,
                              self.allowed_extensions, self.excluded_rel)
            indexer.index_all(
                progress_callback=lambda c, t, f: self.progress.emit(c, t, f),
                loading_callback=lambda: self.model_loading.emit(),
            )
            self.finished.emit("OK")
        except Exception as e:
            self.finished.emit(f"Error: {e}")

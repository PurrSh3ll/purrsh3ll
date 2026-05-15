
import os
import codecs

from PyQt6.QtWidgets import (
    QWidget, QLabel, QHBoxLayout, QVBoxLayout,
    QSizePolicy, QScrollArea
)
from PyQt6.QtCore import Qt, QObject, QThread, pyqtSignal

from file_loaders.psnmap_script import ScriptLauncher
from file_loaders.base_file_loader import _store_chunks

class Worker(QObject):
    finished = pyqtSignal(str, str)

    def __init__(self, file_path, chunk_size=256 * 1024, parent=None):
        super().__init__()
        self.file_path = file_path
        self.chunk_size = chunk_size
        self.parent = parent

    def run(self):
        try:
            chunks = []
            decoder = codecs.getincrementaldecoder("utf-8")()

            with open(self.file_path, "rb") as f:
                while True:
                    raw = f.read(self.chunk_size)
                    if not raw:
                        break
                    text = decoder.decode(raw, final=False)
                    if text:
                        chunks.append(text)

                tail = decoder.decode(b"", final=True)
                if tail:
                    chunks.append(tail)

            _store_chunks(self.parent, self.file_path, chunks)

            full_text = "".join(chunks)
            self.finished.emit(self.file_path, full_text)

        except Exception as e:
            self.finished.emit(self.file_path, f"__ERROR__:{e}")

class Purr_file:
    def __init__(self):
        self.thread = None
        self.worker = None
        self.target_widget = None

    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        self._controller = parent

        scroll = QScrollArea(parent=parent.widgets['execution_tabs'])
        scroll.setWidgetResizable(True)

        container = QWidget(parent=scroll)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(6, 6, 6, 6)
        scroll.setWidget(container)
        scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        file_name = os.path.basename(path)

        label = QLabel(f"⏳ Loading {file_name} ...", container)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        wrapper = QWidget(container)
        w_layout = QHBoxLayout(wrapper)
        w_layout.addStretch()
        w_layout.addWidget(label)
        w_layout.addStretch()

        layout.addWidget(wrapper, alignment=Qt.AlignmentFlag.AlignCenter)

        self.target_widget = container if target_widget is None else target_widget

        self.thread = QThread()
        self.worker = Worker(path, parent=parent)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._on_finished)
        self.worker.finished.connect(self.thread.quit)

        if threads_list is not None:
            threads_list.append(self.thread)

        self.thread.start()

        self._loading_scroll = scroll
        return scroll

    def _on_finished(self, path, content):
        if self.target_widget is None:
            return

        layout = self.target_widget.layout()
        if layout is None:
            return

        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        if content.startswith("__ERROR__:"):
            err = content.split(":", 1)[1]
            label = QLabel(f"Error:\n{err}", parent=self._loading_scroll)
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(label)
            return

        main = QWidget(parent=self._loading_scroll)
        main_layout = QVBoxLayout(main)
        layout.addWidget(main)

        script_launcher = ScriptLauncher(
            parent=main,
            path=path,
            controller=self._controller,
            data = content
        )
        main_layout.addWidget(script_launcher)
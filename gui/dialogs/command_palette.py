import os
import logging
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QLineEdit, QListWidget,
    QListWidgetItem, QLabel, QApplication, QSizePolicy
)
from PyQt6.QtCore import Qt, QEvent
from PyQt6.QtGui import QKeyEvent, QFont

logger = logging.getLogger(__name__)


class CommandPalette(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(
            parent,
            Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint
        )
        self.c = controller
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, False)
        self._entries = []
        self._build_ui()

    def _build_ui(self):
        self.setFixedWidth(560)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Open file...  (↑↓ navigate, Enter open, Esc close)")
        self._search.textChanged.connect(self._on_text_changed)
        layout.addWidget(self._search)

        self._list = QListWidget()
        self._list.setMaximumHeight(380)
        self._list.setMinimumHeight(0)
        self._list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        self._list.itemActivated.connect(self._open_selected)

        font = QFont()
        font.setPointSize(9)
        self._list.setFont(font)
        layout.addWidget(self._list)

        self._no_results = QLabel("No results")
        self._no_results.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._no_results.setVisible(False)
        layout.addWidget(self._no_results)

    def _collect_entries(self):
        entries = []
        for base in (self.c.app_modules_path, self.c.user_modules_path):
            base_parent = os.path.dirname(base)
            for dirpath, dirs, files in os.walk(base):
                dirs.sort(key=str.lower)
                for filename in sorted(files, key=str.lower):
                    full_path = os.path.join(dirpath, filename)
                    rel = os.path.relpath(full_path, base_parent)
                    entries.append((filename.lower(), filename, rel, full_path))
        return entries

    def open_palette(self):
        self._entries = self._collect_entries()
        self._search.clear()
        self._on_text_changed("")
        self._position_on_parent()
        self.show()
        self.raise_()
        self.activateWindow()
        self._search.setFocus()

    def _position_on_parent(self):
        parent = self.parent()
        self.adjustSize()
        if parent and parent.isVisible():
            pg = parent.geometry()
            x = pg.x() + (pg.width() - self.width()) // 2
            y = pg.y() + pg.height() // 5
        else:
            screen = QApplication.primaryScreen().geometry()
            x = screen.x() + (screen.width() - self.width()) // 2
            y = screen.y() + screen.height() // 5
        self.move(x, y)

    def _on_text_changed(self, text):
        self._list.clear()
        needle = text.strip().lower()
        count = 0
        for name_lower, filename, rel, full_path in self._entries:
            if not needle or needle in name_lower or needle in rel.lower():
                item = QListWidgetItem(f"  {filename}\n  {rel}")
                item.setData(Qt.ItemDataRole.UserRole, full_path)
                self._list.addItem(item)
                count += 1
                if count >= 100:
                    break

        if count > 0:
            self._list.setCurrentRow(0)
            self._list.setVisible(True)
            self._no_results.setVisible(False)
        else:
            self._list.setVisible(False)
            self._no_results.setVisible(True)

        self.adjustSize()

    def _open_selected(self, item=None):
        if item is None:
            item = self._list.currentItem()
        if item is None:
            return
        full_path = item.data(Qt.ItemDataRole.UserRole)
        self.hide()
        try:
            self.c.open_new_tab_for_terminal(file=full_path)
        except Exception:
            logger.error("CommandPalette: failed to open %s", full_path, exc_info=True)

    def keyPressEvent(self, event: QKeyEvent):
        key = event.key()
        if key == Qt.Key.Key_Escape:
            self.hide()
        elif key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._open_selected()
        elif key == Qt.Key.Key_Down:
            row = self._list.currentRow()
            if row < self._list.count() - 1:
                self._list.setCurrentRow(row + 1)
            self._search.setFocus()
        elif key == Qt.Key.Key_Up:
            row = self._list.currentRow()
            if row > 0:
                self._list.setCurrentRow(row - 1)
            self._search.setFocus()
        else:
            super().keyPressEvent(event)

    def changeEvent(self, event):
        if event.type() == QEvent.Type.ActivationChange and not self.isActiveWindow():
            self.hide()
        super().changeEvent(event)

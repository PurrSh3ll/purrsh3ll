import json
import logging
import os
import re
import uuid

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QComboBox,
    QPushButton, QScrollArea, QLabel, QDialog, QPlainTextEdit,
    QCheckBox, QInputDialog, QApplication, QSizePolicy, QFrame,
)

logger = logging.getLogger(__name__)

_DEFAULT_CATEGORIES = ["Recon", "Exploit", "Post", "Web", "Crypto", "Misc"]


class SnippetAddEditDialog(QDialog):
    def __init__(self, parent, controller, snippet=None):
        super().__init__(parent)
        self.c = controller
        self.setWindowTitle("Edit Snippet" if snippet else "New Snippet")
        self.setMinimumWidth(440)
        self.setModal(True)
        self._snippet = snippet or {}
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(12, 12, 12, 12)

        self._title_edit = QLineEdit()
        self._title_edit.setPlaceholderText("Snippet title...")
        self._title_edit.setText(self._snippet.get("title", ""))
        layout.addWidget(QLabel("Title:"))
        layout.addWidget(self._title_edit)

        self._cat_combo = QComboBox()
        self._cat_combo.setEditable(True)
        for cat in _DEFAULT_CATEGORIES:
            self._cat_combo.addItem(cat)
        saved_cat = self._snippet.get("category", "")
        if saved_cat:
            idx = self._cat_combo.findText(saved_cat)
            self._cat_combo.setCurrentIndex(idx) if idx >= 0 else self._cat_combo.setCurrentText(saved_cat)
        layout.addWidget(QLabel("Category:"))
        layout.addWidget(self._cat_combo)

        self._content_edit = QPlainTextEdit()
        self._content_edit.setPlaceholderText("Snippet content...  use {VARIABLE} for dynamic placeholders")
        self._content_edit.setPlainText(self._snippet.get("content", ""))
        self._content_edit.setMinimumHeight(120)
        layout.addWidget(QLabel("Content:"))
        layout.addWidget(self._content_edit)

        self._fav_check = QCheckBox("Mark as favorite (shown at top)")
        self._fav_check.setChecked(self._snippet.get("favorite", False))
        layout.addWidget(self._fav_check)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_ok = QPushButton("Save")
        btn_cancel = QPushButton("Cancel")
        btn_ok.setDefault(True)
        btn_ok.clicked.connect(self.accept)
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_ok)
        btn_row.addWidget(btn_cancel)
        layout.addLayout(btn_row)

    def get_data(self):
        return {
            "id": self._snippet.get("id") or str(uuid.uuid4())[:8],
            "title": self._title_edit.text().strip() or "Untitled",
            "category": self._cat_combo.currentText().strip() or "Misc",
            "content": self._content_edit.toPlainText(),
            "favorite": self._fav_check.isChecked(),
        }


class SnippetRow(QWidget):
    def __init__(self, snippet, panel, parent=None):
        super().__init__(parent)
        self._snippet = snippet
        self._panel = panel
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 3, 4, 0)
        layout.setSpacing(1)

        top_row = QHBoxLayout()
        top_row.setSpacing(2)

        fav = "★ " if self._snippet.get("favorite") else "  "
        title_label = QLabel(f"{fav}{self._snippet['title']}")
        title_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        top_row.addWidget(title_label)

        for icon, tooltip, cb in [
            ("→T", "Send to terminal", self._send_to_terminal),
            ("📋", "Copy to clipboard", self._copy_to_clipboard),
            ("✏️", "Edit", self._edit),
            ("🗑", "Delete", self._delete),
        ]:
            btn = QPushButton(icon)
            btn.setToolTip(tooltip)
            btn.setFixedWidth(26)
            btn.setFixedHeight(22)
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            btn.clicked.connect(cb)
            top_row.addWidget(btn)

        layout.addLayout(top_row)

        content = self._snippet.get("content", "")
        first_line = content.split("\n")[0]
        preview = first_line[:72] + ("…" if len(first_line) > 72 else "")
        if preview:
            preview_label = QLabel(preview)
            preview_label.setObjectName("snippet_preview")
            preview_label.setWordWrap(False)
            layout.addWidget(preview_label)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setObjectName("snippet_sep")
        layout.addWidget(sep)

    def _resolve_placeholders(self, content):
        placeholders = re.findall(r'\{([A-Za-z_][A-Za-z0-9_]*)\}', content)
        for name in placeholders:
            value, ok = QInputDialog.getText(
                self, "Placeholder", f"Value for {{{name}}}:"
            )
            if not ok:
                return None
            content = content.replace(f"{{{name}}}", value)
        return content

    def _send_to_terminal(self):
        content = self._snippet.get("content", "")
        resolved = self._resolve_placeholders(content)
        if resolved is None:
            return
        c = self._panel.c
        term_tabs = c.widgets.get("terminal_tabs")
        if not term_tabs:
            return
        wrapper = term_tabs.widget(term_tabs.currentIndex())
        if wrapper is None:
            return
        term = c.wrapper_to_console.get(wrapper)
        if term is None:
            return
        try:
            term.sendText(resolved + "\n")
        except Exception:
            logger.error("Failed to send snippet to terminal", exc_info=True)

    def _copy_to_clipboard(self):
        QApplication.clipboard().setText(self._snippet.get("content", ""))

    def _edit(self):
        dlg = SnippetAddEditDialog(self._panel, self._panel.c, self._snippet)
        dlg.setStyleSheet(self._panel.c.dialog_stylesheet)
        if dlg.exec():
            self._panel.update_snippet(dlg.get_data())

    def _delete(self):
        self._panel.delete_snippet(self._snippet["id"])


class SnippetPanel(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.c = controller
        self._snippets = []
        self._load()
        self._build_ui()
        self._refresh()

    def _data_path(self):
        return os.path.join(self.c.base_path, "appdata", "snippets.json")

    def _load(self):
        path = self._data_path()
        if not os.path.exists(path):
            self._snippets = []
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._snippets = json.load(f).get("snippets", [])
        except Exception:
            logger.warning("Failed to load snippets", exc_info=True)
            self._snippets = []

    def _save(self):
        try:
            with open(self._data_path(), "w", encoding="utf-8") as f:
                json.dump({"snippets": self._snippets}, f, indent=2, ensure_ascii=False)
        except Exception:
            logger.warning("Failed to save snippets", exc_info=True)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(4)

        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍 Search snippets...")
        self._search.textChanged.connect(self._refresh)
        toolbar.addWidget(self._search)

        self._cat_filter = QComboBox()
        self._cat_filter.addItem("All")
        self._cat_filter.setFixedWidth(90)
        self._cat_filter.currentTextChanged.connect(self._refresh)
        toolbar.addWidget(self._cat_filter)

        add_btn = QPushButton("＋")
        add_btn.setFixedWidth(28)
        add_btn.setFixedHeight(24)
        add_btn.setToolTip("Add snippet  (Ctrl+N)")
        add_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        add_btn.clicked.connect(self._add)
        toolbar.addWidget(add_btn)

        layout.addLayout(toolbar)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self._list_widget = QWidget()
        self._list_layout = QVBoxLayout(self._list_widget)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._list_layout.setSpacing(0)
        self._list_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._scroll.setWidget(self._list_widget)
        layout.addWidget(self._scroll)

        self._empty_label = QLabel("No snippets.\nPress + to add one.")
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.hide()
        layout.addWidget(self._empty_label)

        shortcut = QShortcut(QKeySequence("Ctrl+N"), self)
        shortcut.activated.connect(self._add)

    def _categories(self):
        return sorted({s.get("category", "Misc") for s in self._snippets})

    def _refresh_cat_filter(self):
        current = self._cat_filter.currentText()
        self._cat_filter.blockSignals(True)
        self._cat_filter.clear()
        self._cat_filter.addItem("All")
        for cat in self._categories():
            self._cat_filter.addItem(cat)
        idx = self._cat_filter.findText(current)
        if idx >= 0:
            self._cat_filter.setCurrentIndex(idx)
        self._cat_filter.blockSignals(False)

    def _refresh(self):
        while self._list_layout.count():
            item = self._list_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        needle = self._search.text().strip().lower()
        cat = self._cat_filter.currentText()

        ordered = sorted(
            self._snippets,
            key=lambda s: (not s.get("favorite", False), s.get("title", "").lower())
        )
        matches = [
            s for s in ordered
            if (cat == "All" or s.get("category") == cat)
            and (not needle or needle in s.get("title", "").lower() or needle in s.get("content", "").lower())
        ]

        if matches:
            self._scroll.show()
            self._empty_label.hide()
            for s in matches:
                self._list_layout.addWidget(SnippetRow(s, self))
        else:
            self._scroll.hide()
            self._empty_label.show()

        self._refresh_cat_filter()

    def _add(self):
        dlg = SnippetAddEditDialog(self, self.c)
        dlg.setStyleSheet(self.c.dialog_stylesheet)
        if dlg.exec():
            self._snippets.append(dlg.get_data())
            self._save()
            self._refresh()

    def update_snippet(self, updated):
        for i, s in enumerate(self._snippets):
            if s["id"] == updated["id"]:
                self._snippets[i] = updated
                break
        self._save()
        self._refresh()

    def delete_snippet(self, snippet_id):
        self._snippets = [s for s in self._snippets if s["id"] != snippet_id]
        self._save()
        self._refresh()

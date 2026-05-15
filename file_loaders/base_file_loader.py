import logging
import os
import re
import threading
import tempfile
import stat

logger = logging.getLogger(__name__)

from PyQt6.sip import isdeleted
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea,
    QPushButton, QLineEdit, QCheckBox, QComboBox, QListView,
    QSizePolicy, QTextEdit, QApplication
)
from PyQt6.QtCore import Qt, QThread, QTimer, QRegularExpression
from PyQt6.QtGui import QTextCharFormat, QColor, QTextCursor

from gui.widgets.custom_line_edit import ExpandingLineEdit
from file_loaders.viewer_widgets import Worker, TextEditWithLineNumbers

_MAX_CHUNKS_ENTRIES = 50

def _store_chunks(parent, path, chunks):
    if parent is None or path is None:
        return
    if not hasattr(parent, "text_chunks"):
        parent.text_chunks = {}
    parent.text_chunks.pop(path, None)
    parent.text_chunks[path] = chunks
    while len(parent.text_chunks) > _MAX_CHUNKS_ENTRIES:
        parent.text_chunks.pop(next(iter(parent.text_chunks)))

class BaseFileLoader:

    def __init__(self):
        self.thread = None
        self.worker = None
        self.target_widget = None
        self.parent = None
        self._controller = None
        self.text_widget = None
        self.save_timer = None
        self.search_debounce_timer = None

        self._loading_scroll = None
        self._loading_container = None
        self._current_path = None

        self._chunks = []
        self._nav_state = {"index": 0, "total": 0}
        self._last_saved = {"text": None}
        self._zoom_state = {"level": 0}
        self._matches_store = {"shown": [], "positions": [], "total": 0}
        self._nav_index = {"idx": -1}
        self._searching_paused = {"val": False}

        self._search_field = None
        self._method_box = None
        self._find_prev_btn = None
        self._find_next_btn = None
        self._replace_field = None
        self._replace_container = None
        self._flags_container = None
        self._literal_checkbox = None
        self._flags_ignore = None
        self._flags_multiline = None
        self._flags_dotall = None
        self._flags_verbose = None
        self._count_label = None
        self._edit_checkbox = None
        self._options_btn = None
        self._zoom_out_btn = None
        self._zoom_in_btn = None
        self._chunk_edit = None
        self._prev_btn = None
        self._next_btn = None
        self._total_label = None
        self._file_info_label = None

    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        self.parent = parent
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
        label.setWordWrap(True)
        label.setMinimumWidth(0)

        wrapper = QWidget(container)
        w_layout = QHBoxLayout(wrapper)
        w_layout.setContentsMargins(0, 0, 0, 0)
        w_layout.addStretch(1)
        w_layout.addWidget(label)
        w_layout.addStretch(1)
        wrapper.setMaximumWidth(400)

        layout.addWidget(wrapper, alignment=Qt.AlignmentFlag.AlignCenter)
        container.setLayout(layout)

        self.target_widget = container if target_widget is None else target_widget

        th = QThread()
        self.thread = th
        self.worker = self._create_worker(path, parent)
        self.worker.moveToThread(th)

        th.started.connect(self.worker.run)
        self.worker.finished.connect(self._on_finished)
        self.worker.finished.connect(th.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        th.finished.connect(th.deleteLater)
        th.finished.connect(lambda th_ref=th: self._cleanup_thread(threads_list, th_ref))

        scroll._loader = self

        if threads_list is not None:
            threads_list.append(th)

        th.start()

        self._loading_label = label
        self._loading_container = container
        self._loading_scroll = scroll
        return scroll

    def _create_worker(self, path, parent):
        return Worker(path, parent=parent)

    def _create_text_widget(self):
        return TextEditWithLineNumbers(controller=self.parent, parent=self._loading_scroll)

    def _extra_control_bar_widgets(self, control_bar_widget, control_bar_layout):
        pass

    def _extra_layout_widgets(self, layout):
        pass

    def _post_update_file_info(self, num_lines):
        pass

    def _cleanup_highlighter(self):
        pass

    def _on_finished(self, path, content):
        if self.target_widget is None or isdeleted(self.target_widget):
            return
        layout = self.target_widget.layout()
        if layout is None:
            return

        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        if isinstance(content, str) and content.startswith("__ERROR__:"):
            err_text = content.split(":", 1)[1]
            err_label = QLabel(f"⚠️ Error reading file:\n{err_text}", parent=self._loading_scroll)
            err_label.setWordWrap(True)
            err_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(err_label)
        else:
            self._current_path = path

            if self.parent is not None and hasattr(self.parent, "text_chunks"):
                self._chunks = self.parent.text_chunks.get(path, [])
            if not self._chunks and content:
                self._chunks = [content]
            total_chunks = len(self._chunks)
            self._nav_state = {"index": 0, "total": total_chunks}

            self._build_control_bar(layout)
            self._build_flags_bar(layout)

            if total_chunks > 1:
                self._build_chunk_nav_ui(layout)

            self.text_widget = self._create_text_widget()
            self.parent.text_loaders.append(self.text_widget)
            line_color = self.parent.qss_QPainter.get("painter_lines")
            self.text_widget.setStyleSheet(
                f"border-top: 2px solid {line_color}; border-bottom: none; border-left: none; border-right: none;"
            )
            self.text_widget.setReadOnly(True)
            self.text_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            layout.addWidget(self.text_widget)

            self._extra_layout_widgets(layout)
            self._build_file_info_label(layout)

            self._setup_zoom()
            self._setup_save_timer()
            self._setup_edit_toggle()

            if total_chunks == 0:
                self.text_widget.setPlaceholderText("This file is empty.")
                self.text_widget.setPlainText("")
                self._last_saved = {"text": ""}
            else:
                self._nav_state["index"] = 0
                first = self._chunks[0] if self._chunks else (content or "")
                self.text_widget.setPlainText(first)
                self._last_saved = {"text": first}

            layout.addWidget(self.text_widget)

            self._setup_search()

            if total_chunks > 1:
                self._setup_chunk_nav_callbacks()
                self._update_view()

            try:
                self._update_file_info()
            except Exception:
                pass

        if self.thread is not None:
            self.thread.quit()

    def _build_control_bar(self, layout):
        control_bar_widget = QWidget(parent=self._loading_scroll)
        control_bar_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        control_bar_layout = QHBoxLayout(control_bar_widget)
        control_bar_layout.setContentsMargins(0, 0, 0, 0)
        control_bar_layout.setSpacing(6)

        self._zoom_out_btn = QPushButton("➖", parent=control_bar_widget)
        self._zoom_in_btn = QPushButton("➕", parent=control_bar_widget)
        self._edit_checkbox = QCheckBox("Edit", parent=control_bar_widget)
        self._zoom_out_btn.setFixedSize(28, 28)
        self._zoom_in_btn.setFixedSize(28, 28)

        control_bar_layout.addWidget(self._zoom_out_btn)
        control_bar_layout.addWidget(self._zoom_in_btn)
        control_bar_layout.addWidget(self._edit_checkbox)

        self._search_field = ExpandingLineEdit(parent=control_bar_widget)
        self._search_field.setPlaceholderText("Search...")
        self._search_field.setMinimumWidth(120)
        control_bar_layout.addWidget(self._search_field)

        self._method_box = QComboBox(parent=control_bar_widget)
        self._method_box.setView(QListView())
        self._method_box.addItems(["find", "replace", "regex", "replace regex"])
        control_bar_layout.addWidget(self._method_box)

        self._find_prev_btn = QPushButton("▲", parent=control_bar_widget)
        self._find_next_btn = QPushButton("▼", parent=control_bar_widget)
        self._find_prev_btn.setEnabled(False)
        self._find_next_btn.setEnabled(False)
        self._find_prev_btn.setFixedSize(28, 28)
        self._find_next_btn.setFixedSize(28, 28)
        self._find_prev_btn.setVisible(True)
        self._find_next_btn.setVisible(True)
        control_bar_layout.addWidget(self._find_prev_btn)
        control_bar_layout.addWidget(self._find_next_btn)

        self._replace_container = QWidget(parent=control_bar_widget)
        replace_layout = QHBoxLayout(self._replace_container)
        replace_layout.setContentsMargins(0, 0, 0, 0)
        replace_layout.setSpacing(6)
        self._replace_field = QLineEdit(parent=control_bar_widget)
        self._replace_field.setPlaceholderText("Replace with...")
        self._replace_field.setMinimumWidth(120)
        replace_btn = QPushButton("Replace", parent=control_bar_widget)
        replace_btn.clicked.connect(self._on_replace_clicked)
        replace_layout.addWidget(self._replace_field)
        replace_layout.addWidget(replace_btn)
        control_bar_layout.addWidget(self._replace_container)
        self._replace_container.setVisible(False)

        self._options_btn = QPushButton("☰", parent=control_bar_widget)
        self._options_btn.setFixedSize(28, 28)
        control_bar_layout.addWidget(self._options_btn)

        self._count_label = QLabel("0 matches", parent=control_bar_widget)
        control_bar_layout.addWidget(self._count_label)

        copy_matches_btn = QPushButton("Copy matches", parent=control_bar_widget)
        copy_matches_btn.clicked.connect(self._copy_matches_to_clipboard)
        control_bar_layout.addWidget(copy_matches_btn)

        self._extra_control_bar_widgets(control_bar_widget, control_bar_layout)

        control_bar_layout.addStretch()
        layout.addWidget(control_bar_widget)

        self._method_box.currentTextChanged.connect(self._on_method_changed)
        self._find_next_btn.clicked.connect(self._on_find_next)
        self._find_prev_btn.clicked.connect(self._on_find_prev)

    def _build_flags_bar(self, layout):
        self._flags_container = QWidget(parent=self._loading_scroll)
        self._flags_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._flags_container.setMaximumHeight(36)
        flags_layout = QHBoxLayout(self._flags_container)
        flags_layout.setContentsMargins(0, 0, 0, 0)
        flags_layout.setSpacing(10)

        self._literal_checkbox = QCheckBox("LITERAL", parent=self._flags_container)
        self._flags_ignore = QCheckBox("IGNORECASE", parent=self._flags_container)
        self._flags_multiline = QCheckBox("MULTILINE", parent=self._flags_container)
        self._flags_dotall = QCheckBox("DOTALL", parent=self._flags_container)
        self._flags_verbose = QCheckBox("VERBOSE", parent=self._flags_container)

        for cb in (self._literal_checkbox, self._flags_ignore, self._flags_multiline,
                   self._flags_dotall, self._flags_verbose):
            flags_layout.addWidget(cb)

        flags_layout.addStretch()
        layout.addWidget(self._flags_container)
        self._flags_container.setVisible(False)
        self._options_btn.clicked.connect(self._toggle_flags)

    def _build_chunk_nav_ui(self, layout):
        top_bar_widget = QWidget(parent=self._loading_scroll)
        top_bar_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        top_bar_layout = QHBoxLayout(top_bar_widget)
        top_bar_layout.setContentsMargins(0, 0, 0, 0)
        top_bar_layout.setSpacing(6)

        self._prev_btn = QPushButton("◀", parent=top_bar_widget)
        self._next_btn = QPushButton("▶", parent=top_bar_widget)
        self._prev_btn.setFixedSize(28, 28)
        self._next_btn.setFixedSize(28, 28)
        self._chunk_edit = QLineEdit("1", parent=top_bar_widget)
        self._chunk_edit.setFixedWidth(40)
        self._total_label = QLabel(f"/{self._nav_state['total']} pages", parent=top_bar_widget)
        self._total_label.setEnabled(False)
        self._total_label.setStyleSheet("font-style: italic;")

        top_bar_layout.addWidget(self._prev_btn)
        top_bar_layout.addWidget(self._next_btn)
        top_bar_layout.addWidget(self._chunk_edit)
        top_bar_layout.addWidget(self._total_label)
        top_bar_layout.addStretch()
        layout.addWidget(top_bar_widget)

    def _build_file_info_label(self, layout):
        self._file_info_label = QLabel(parent=self._loading_scroll)
        self._file_info_label.setStyleSheet("font-style: italic;")
        self._file_info_label.setText("File size: N/A | Lines: 0 | Characters: 0 | Permissions: N/A")
        self._file_info_label.setEnabled(False)
        layout.addWidget(self._file_info_label)
        self.text_widget.textChanged.connect(self._update_file_info)

    def _on_method_changed(self, text):
        self._replace_container.setVisible(text in ("replace", "replace regex"))
        is_search_mode = text in ("regex", "find")
        self._find_prev_btn.setVisible(is_search_mode)
        self._find_next_btn.setVisible(is_search_mode)

        if text == "find":
            self._search_field.setPlaceholderText("Search...")
            self._options_btn.hide()
        elif text == "replace":
            self._search_field.setPlaceholderText("Search...")
            self._options_btn.hide()
        elif text == "regex":
            self._search_field.setPlaceholderText("Search (regex)...")
            self._options_btn.show()
        elif text == "replace regex":
            self._search_field.setPlaceholderText("Search (regex)...")
            self._options_btn.show()

        if not is_search_mode:
            self._nav_index["idx"] = -1

    def _toggle_flags(self):
        self._flags_container.setVisible(not self._flags_container.isVisible())

    def _copy_matches_to_clipboard(self):
        shown = self._matches_store.get("shown", [])
        if not shown:
            return
        try:
            QApplication.clipboard().setText("\n".join(shown))
        except Exception:
            pass

    MIN_ZOOM = -10
    MAX_ZOOM = 40

    def _setup_zoom(self):
        self._zoom_state = {"level": 0}
        self._zoom_out_btn.clicked.connect(self._zoom_out)
        self._zoom_in_btn.clicked.connect(self._zoom_in)
        self._update_zoom_buttons()

    def _zoom_in(self):
        if self._zoom_state["level"] < self.MAX_ZOOM:
            try:
                self.text_widget.zoomIn(1)
                self._zoom_state["level"] += 1
            except Exception:
                pass
        self._update_zoom_buttons()

    def _zoom_out(self):
        if self._zoom_state["level"] > self.MIN_ZOOM:
            try:
                self.text_widget.zoomOut(1)
                self._zoom_state["level"] -= 1
            except Exception:
                pass
        self._update_zoom_buttons()

    def _update_zoom_buttons(self):
        try:
            self._zoom_out_btn.setEnabled(self._zoom_state["level"] > self.MIN_ZOOM)
            self._zoom_in_btn.setEnabled(self._zoom_state["level"] < self.MAX_ZOOM)
        except Exception:
            pass

    def _setup_save_timer(self):
        self.save_timer = QTimer(self.text_widget)
        self.save_timer.setSingleShot(True)
        self.save_timer.setInterval(1000)
        self.save_timer.timeout.connect(self._on_save_timer_timeout)

    def _on_save_timer_timeout(self):
        self._save_current_chunk()

    def _save_current_chunk(self):
        idx = self._nav_state["index"]
        new_text = self.text_widget.toPlainText()
        if self._last_saved["text"] == new_text:
            return
        if idx >= len(self._chunks):
            self._chunks.extend([""] * (idx - len(self._chunks) + 1))
        self._chunks[idx] = new_text
        self._last_saved["text"] = new_text
        _store_chunks(self.parent, self._current_path, self._chunks)
        try:
            chunks_copy = list(self._chunks)
            t = threading.Thread(
                target=self._write_chunks_to_disk, args=(chunks_copy, self._current_path), daemon=True
            )
            t.start()
        except Exception:
            logger.error("Failed to start file write thread for %s", self._current_path, exc_info=True)

    def _setup_edit_toggle(self):
        self._edit_checkbox.stateChanged.connect(self._on_edit_toggled)
        self.text_widget.textChanged.connect(self._on_text_changed)

    def _on_text_changed(self):
        if not self._edit_checkbox.isChecked():
            return
        current = self.text_widget.toPlainText()
        if self._last_saved["text"] != current:
            self.save_timer.start()

    def _on_edit_toggled(self, state):
        checked = bool(state)
        if checked:
            self.text_widget.setReadOnly(False)
            self._last_saved["text"] = self.text_widget.toPlainText()
            self.save_timer.stop()
            self.text_widget.setFocus()
        else:
            self.text_widget.setReadOnly(True)
            self.save_timer.stop()
            self._save_current_chunk()

    def _update_file_info(self):
        try:
            try:
                size = os.path.getsize(self._current_path)
                if size < 1024:
                    size_str = f"{size} B"
                elif size < 1024 ** 2:
                    size_str = f"{size / 1024:.1f} KB"
                else:
                    size_str = f"{size / 1024 ** 2:.1f} MB"
            except Exception:
                size_str = "N/A"

            try:
                txt = self.text_widget.toPlainText()
                num_chars = len(txt)
                num_lines = txt.count("\n") + (1 if txt else 0)
            except Exception:
                num_chars = 0
                num_lines = 0

            try:
                st = os.stat(self._current_path)
                permissions = stat.filemode(st.st_mode)
            except Exception:
                permissions = "N/A"

            self._file_info_label.setText(
                f"File size: {size_str} | Lines: {num_lines} | Characters: {num_chars} | Permissions: {permissions}"
            )

            self._post_update_file_info(num_lines)

        except Exception:
            try:
                self._file_info_label.setText("File size: N/A | Lines: 0 | Characters: 0 | Permissions: N/A")
            except Exception:
                pass

    def _setup_search(self):
        self._matches_store = {"shown": [], "positions": [], "total": 0}
        self._nav_index = {"idx": -1}
        self._searching_paused = {"val": False}

        self.search_debounce_timer = QTimer(self.text_widget)
        self.search_debounce_timer.setSingleShot(True)
        self.search_debounce_timer.setInterval(300)
        self.search_debounce_timer.timeout.connect(self._on_debounce_timeout)

        self._search_field.textChanged.connect(self._restart_debounce)
        for cb in (self._literal_checkbox, self._flags_ignore, self._flags_multiline,
                   self._flags_dotall, self._flags_verbose):
            cb.stateChanged.connect(self._restart_debounce)

    def _restart_debounce(self, _=None):
        if self.search_debounce_timer is not None:
            self.search_debounce_timer.start()

    def _on_debounce_timeout(self):
        self._update_count_and_highlight(self._search_field.text())

    def _pause_search(self):
        self._searching_paused["val"] = True
        try:
            self.search_debounce_timer.stop()
        except Exception:
            pass

    def _resume_search(self):
        self._searching_paused["val"] = False
        try:
            if self._search_field.text().strip():
                self.search_debounce_timer.start()
            else:
                self.search_debounce_timer.stop()
        except Exception:
            pass

    def _clear_search_state(self):
        try:
            try:
                self.text_widget.setExtraSelections([])
            except Exception:
                pass
            try:
                self._matches_store["shown"].clear()
                self._matches_store["positions"].clear()
                self._matches_store["total"] = 0
            except Exception:
                pass
            try:
                self._nav_index["idx"] = -1
            except Exception:
                pass
            try:
                self._count_label.setText("0 matches")
                self._find_prev_btn.setEnabled(False)
                self._find_next_btn.setEnabled(False)
            except Exception:
                pass
        except Exception:
            pass

    def _qre_options_from_checks(self):
        opts = QRegularExpression.PatternOption(0)
        if self._flags_ignore.isChecked():
            opts |= QRegularExpression.PatternOption.CaseInsensitiveOption
        if self._flags_multiline.isChecked():
            opts |= QRegularExpression.PatternOption.MultilineOption
        if self._flags_dotall.isChecked():
            opts |= QRegularExpression.PatternOption.DotMatchesEverythingOption
        if self._flags_verbose.isChecked():
            opts |= QRegularExpression.PatternOption.ExtendedPatternSyntaxOption
        return opts

    def _select_match_at(self, idx):
        positions = self._matches_store.get("positions", [])
        if not positions or idx < 0 or idx >= len(positions):
            return
        start, length = positions[idx]
        if start < 0 or length <= 0:
            return
        cursor = QTextCursor(self.text_widget.document())
        cursor.setPosition(start)
        cursor.setPosition(start + length, QTextCursor.MoveMode.KeepAnchor)
        self.text_widget.setTextCursor(cursor)
        self.text_widget.setFocus()

    def _on_find_next(self):
        positions = self._matches_store.get("positions", [])
        if not positions:
            return
        if self._nav_index["idx"] < 0:
            self._nav_index["idx"] = 0
        else:
            self._nav_index["idx"] = (self._nav_index["idx"] + 1) % len(positions)
        self._select_match_at(self._nav_index["idx"])

    def _on_find_prev(self):
        positions = self._matches_store.get("positions", [])
        if not positions:
            return
        if self._nav_index["idx"] < 0:
            self._nav_index["idx"] = len(positions) - 1
        else:
            self._nav_index["idx"] = (self._nav_index["idx"] - 1) % len(positions)
        self._select_match_at(self._nav_index["idx"])

    _MAX_MATCHES = 10_000

    def _update_count_and_highlight(self, txt):
        fmt_search = QTextCharFormat()
        fmt_search.setBackground(QColor("yellow"))
        max_matches = self._MAX_MATCHES

        if self._searching_paused.get("val", False):
            try:
                self.text_widget.setExtraSelections([])
            except Exception:
                pass
            self._count_label.setText("0 matches")
            self._matches_store["shown"] = []
            self._matches_store["positions"] = []
            self._matches_store["total"] = 0
            self._find_prev_btn.setEnabled(False)
            self._find_next_btn.setEnabled(False)
            return

        lit = bool(self._literal_checkbox.isChecked())
        full_text = self.text_widget.toPlainText()
        method = self._method_box.currentText()
        self._nav_index["idx"] = -1

        if not txt:
            self.text_widget.setExtraSelections([])
            self._count_label.setText("0 matches")
            self._matches_store["shown"] = []
            self._matches_store["positions"] = []
            self._matches_store["total"] = 0
            self._find_prev_btn.setEnabled(False)
            self._find_next_btn.setEnabled(False)
            return

        try:
            selections = []
            total = 0
            shown = 0
            shown_texts = []
            shown_positions = []

            if method in ("find", "replace"):
                needle = txt.lower()
                hay = full_text.lower()
                start = 0
                while shown < max_matches:
                    idx = hay.find(needle, start)
                    if idx == -1:
                        break
                    cursor = QTextCursor(self.text_widget.document())
                    cursor.setPosition(idx)
                    cursor.setPosition(idx + len(txt), QTextCursor.MoveMode.KeepAnchor)
                    sel = QTextEdit.ExtraSelection()
                    sel.cursor = cursor
                    sel.format = fmt_search
                    selections.append(sel)
                    shown_texts.append(full_text[idx:idx + len(txt)])
                    shown_positions.append((idx, len(txt)))
                    shown += 1
                    total += 1
                    if len(txt) == 0:
                        break
                    start = idx + len(txt)
            else:
                pat = QRegularExpression.escape(txt) if lit else txt
                qre = QRegularExpression(pat)
                qre.setPatternOptions(self._qre_options_from_checks())

                if not qre.isValid():
                    self.text_widget.setExtraSelections([])
                    self._matches_store["shown"] = []
                    self._matches_store["positions"] = []
                    self._matches_store["total"] = 0
                    self._nav_index["idx"] = -1
                    self._count_label.setText("0 matches")
                    self._find_prev_btn.setEnabled(False)
                    self._find_next_btn.setEnabled(False)
                    return

                it = qre.globalMatch(full_text)
                while it.hasNext():
                    m = it.next()
                    total += 1
                    if shown < max_matches:
                        start = m.capturedStart()
                        length = m.capturedLength()
                        if start >= 0 and length > 0:
                            cursor = QTextCursor(self.text_widget.document())
                            cursor.setPosition(start)
                            cursor.setPosition(start + length, QTextCursor.MoveMode.KeepAnchor)
                            sel = QTextEdit.ExtraSelection()
                            sel.cursor = cursor
                            sel.format = fmt_search
                            selections.append(sel)
                            try:
                                shown_texts.append(m.captured(0))
                            except Exception:
                                shown_texts.append(full_text[start:start + length])
                            shown_positions.append((start, length))
                            shown += 1
                    if total > max_matches and shown >= max_matches:
                        break

            self.text_widget.setExtraSelections(selections)
            self._matches_store["shown"] = shown_texts
            self._matches_store["positions"] = shown_positions
            self._matches_store["total"] = total

            if total == max_matches:
                self._count_label.setText(f"{max_matches} matches (reached max limit)")
            else:
                self._count_label.setText(f"{total} matches")

            has_matches = total > 0
            self._find_prev_btn.setEnabled(has_matches)
            self._find_next_btn.setEnabled(has_matches)

        except Exception:
            self.text_widget.setExtraSelections([])
            self._matches_store["shown"] = []
            self._matches_store["positions"] = []
            self._matches_store["total"] = 0
            self._nav_index["idx"] = -1
            self._count_label.setText("0 matches")
            self._find_prev_btn.setEnabled(False)
            self._find_next_btn.setEnabled(False)

    def _on_replace_clicked(self):
        mode = self._method_box.currentText()
        if mode not in ("replace regex", "replace"):
            return
        if not self._edit_checkbox.isChecked():
            return

        needle = self._search_field.text()
        replacement = self._replace_field.text()
        if not needle:
            return

        try:
            full_text = self.text_widget.toPlainText()
        except Exception:
            return

        new_text = full_text
        matches_count = 0

        if mode == "replace":
            try:
                pattern = re.compile(re.escape(needle), re.IGNORECASE)
                matches = list(pattern.finditer(full_text))
                if not matches:
                    return
                new_text = pattern.sub(replacement, full_text)
                matches_count = len(matches)
            except re.error:
                return

        elif mode == "replace regex":
            lit = bool(self._literal_checkbox.isChecked())
            try:
                pat = QRegularExpression.escape(needle) if lit else needle
                qre = QRegularExpression(pat)
                qre.setPatternOptions(self._qre_options_from_checks())

                if not qre.isValid():
                    return

                matches = []
                it = qre.globalMatch(full_text)
                while it.hasNext():
                    m = it.next()
                    s = m.capturedStart()
                    ln = m.capturedLength()
                    if s >= 0 and ln > 0:
                        matches.append((s, ln))

                if not matches:
                    return

                pieces = []
                last = len(full_text)
                for start, length in reversed(matches):
                    pieces.append(full_text[start + length:last])
                    pieces.append(replacement)
                    last = start
                pieces.append(full_text[:last])
                new_text = "".join(reversed(pieces))
                matches_count = len(matches)

            except Exception:
                return

        try:
            try:
                self.text_widget.setUpdatesEnabled(False)
            except Exception:
                pass
            self.text_widget.blockSignals(True)
            try:
                if self._matches_store.get("positions"):
                    self.text_widget.setExtraSelections([])
                    self._matches_store["shown"].clear()
                    self._matches_store["positions"].clear()
                    self._matches_store["total"] = 0
                self.text_widget.setPlainText(new_text)
                self._last_saved["text"] = new_text
            finally:
                self.text_widget.blockSignals(False)
                try:
                    self.text_widget.setUpdatesEnabled(True)
                except Exception:
                    pass
        except Exception:
            try:
                self.text_widget.blockSignals(False)
            except Exception:
                pass

        try:
            QTimer.singleShot(0, self._update_file_info)
        except Exception:
            try:
                self._update_file_info()
            except Exception:
                pass

        try:
            idx = self._nav_state.get("index", 0)
            if idx >= len(self._chunks):
                self._chunks.extend([""] * (idx - len(self._chunks) + 1))
            self._chunks[idx] = new_text

            _store_chunks(self.parent, self._current_path, self._chunks)
            to_write = list(self._chunks)
            t = threading.Thread(
                target=self._write_chunks_to_disk, args=(to_write, self._current_path), daemon=True
            )
            t.start()
        except Exception:
            pass

        try:
            if self._search_field.text().strip():
                self.search_debounce_timer.start()
            else:
                try:
                    self.search_debounce_timer.stop()
                except Exception:
                    pass
        except Exception:
            try:
                self._update_count_and_highlight(self._search_field.text())
            except Exception:
                pass

    def _try_remove_current_chunk_for_nav(self, direction):
        if self.text_widget.toPlainText() != "":
            return False
        idx = self._nav_state["index"]
        if 0 <= idx < len(self._chunks):
            del self._chunks[idx]
            _store_chunks(self.parent, self._current_path, self._chunks)
            try:
                t = threading.Thread(
                    target=self._write_chunks_to_disk, args=(list(self._chunks), self._current_path), daemon=True
                )
                t.start()
            except Exception:
                pass
            self._nav_state["total"] = len(self._chunks)
            if self._nav_state["total"] == 0:
                self._nav_state["index"] = 0
                self._last_saved["text"] = ""
            else:
                if direction == "prev":
                    self._nav_state["index"] = max(0, idx - 1)
                else:
                    self._nav_state["index"] = max(0, min(idx, self._nav_state["total"] - 1))
                self._last_saved["text"] = self._chunks[self._nav_state["index"]]

            if self._total_label is not None:
                self._total_label.setText(f"/{self._nav_state['total']} pages")
            if self._chunk_edit is not None:
                self._chunk_edit.setText(
                    str(self._nav_state["index"] + 1) if self._nav_state["total"] > 0 else "0"
                )
            if self._prev_btn is not None:
                self._prev_btn.setEnabled(self._nav_state["index"] > 0 and self._nav_state["total"] > 0)
            if self._next_btn is not None:
                self._next_btn.setEnabled(self._nav_state["index"] < (self._nav_state["total"] - 1))
            return True
        return False

    def _setup_chunk_nav_callbacks(self):
        self._prev_btn.clicked.connect(self._on_prev_chunk)
        self._next_btn.clicked.connect(self._on_next_chunk)
        self._chunk_edit.returnPressed.connect(self._on_chunk_edit_entered)

    def _on_prev_chunk(self):
        self._pause_search()
        try:
            self.search_debounce_timer.stop()
        except Exception:
            pass

        if self._search_field.text().strip():
            self._clear_search_state()

        if self._try_remove_current_chunk_for_nav("prev"):
            self._update_view()
            if self._search_field.text().strip():
                QTimer.singleShot(0, self._resume_search)
            else:
                self._searching_paused["val"] = False
            return

        if self._edit_checkbox.isChecked():
            self.save_timer.stop()
            self._save_current_chunk()

        self._nav_state["index"] = max(0, self._nav_state["index"] - 1)
        self._update_view()

        if self._search_field.text().strip():
            QTimer.singleShot(0, self._resume_search)
        else:
            self._searching_paused["val"] = False

    def _on_next_chunk(self):
        self._pause_search()
        try:
            self.search_debounce_timer.stop()
        except Exception:
            pass

        if self._search_field.text().strip():
            self._clear_search_state()

        if self._try_remove_current_chunk_for_nav("next"):
            self._update_view()
            if self._search_field.text().strip():
                QTimer.singleShot(0, self._resume_search)
            else:
                self._searching_paused["val"] = False
            return

        if self._edit_checkbox.isChecked():
            self.save_timer.stop()
            self._save_current_chunk()

        self._nav_state["index"] = min(self._nav_state["total"] - 1, self._nav_state["index"] + 1)
        self._update_view()

        if self._search_field.text().strip():
            QTimer.singleShot(0, self._resume_search)
        else:
            self._searching_paused["val"] = False

    def _on_chunk_edit_entered(self):
        txt = self._chunk_edit.text().strip()
        try:
            n = int(txt)
            n = max(1, min(n, self._nav_state["total"]))
            if self._try_remove_current_chunk_for_nav("next"):
                self._update_view()
                return
            if self._edit_checkbox.isChecked():
                self.save_timer.stop()
                self._save_current_chunk()
            self._nav_state["index"] = n - 1
            self._update_view()
        except Exception:
            self._chunk_edit.setText(str(self._nav_state["index"] + 1))

    def _update_view(self):
        if self.parent is not None and hasattr(self.parent, "text_chunks"):
            chunks_local = list(self.parent.text_chunks.get(self._current_path, self._chunks))
        else:
            chunks_local = list(self._chunks)

        self._nav_state["total"] = len(chunks_local)
        idx = self._nav_state.get("index", 0)

        try:
            if not self._search_field.text().strip():
                self._clear_search_state()
        except Exception:
            pass

        if not chunks_local:
            try:
                self.text_widget.setExtraSelections([])
            except Exception:
                pass
            self.text_widget.blockSignals(True)
            try:
                if self.text_widget.toPlainText() != "":
                    self.text_widget.setPlainText("")
                self._last_saved["text"] = ""
            finally:
                self.text_widget.blockSignals(False)
        else:
            idx = max(0, min(idx, len(chunks_local) - 1))
            self._nav_state["index"] = idx
            current_content = chunks_local[idx]

            try:
                self.text_widget.setExtraSelections([])
            except Exception:
                pass

            self.text_widget.blockSignals(True)
            try:
                current_on_widget = self.text_widget.toPlainText()
                if current_on_widget != current_content:
                    try:
                        self.text_widget.setUpdatesEnabled(False)
                    except Exception:
                        pass
                    try:
                        self.text_widget.setPlainText(current_content)
                    finally:
                        try:
                            self.text_widget.setUpdatesEnabled(True)
                        except Exception:
                            pass
                self._last_saved["text"] = current_content
            finally:
                self.text_widget.blockSignals(False)

            try:
                QTimer.singleShot(0, self._update_file_info)
            except Exception:
                try:
                    self._update_file_info()
                except Exception:
                    pass

        if self._chunk_edit is not None:
            self._chunk_edit.setText(
                str(self._nav_state["index"] + 1) if self._nav_state["total"] > 0 else "0"
            )
        if self._total_label is not None:
            self._total_label.setText(f"/{self._nav_state['total']} pages")
        if self._prev_btn is not None:
            self._prev_btn.setEnabled(self._nav_state["index"] > 0 and self._nav_state["total"] > 0)
        if self._next_btn is not None:
            self._next_btn.setEnabled(self._nav_state["index"] < (self._nav_state["total"] - 1))

    def _write_chunks_to_disk(self, chunks_list, path):
        try:
            data = "".join(chunks_list)
            dirpath = os.path.dirname(path) or "."

            old_mode = None
            old_atime = None
            old_mtime = None
            try:
                st = os.stat(path)
                old_mode = stat.S_IMODE(st.st_mode)
                old_atime = st.st_atime
                old_mtime = st.st_mtime
            except FileNotFoundError:
                old_mode = None
            except Exception as e:
                old_mode = None

            tmpf = None
            try:
                tmpf = tempfile.NamedTemporaryFile(
                    mode="wb", delete=False, dir=dirpath, prefix=".tmp_write_", suffix=".tmp"
                )
                try:
                    tmpf.write(data.encode("utf-8"))
                    tmpf.flush()
                    os.fsync(tmpf.fileno())
                except Exception:
                    try:
                        tmpf.close()
                    except Exception:
                        pass
                    try:
                        if os.path.exists(tmpf.name):
                            os.remove(tmpf.name)
                    except Exception:
                        pass
                    raise

                if old_mode is not None:
                    try:
                        try:
                            os.fchmod(tmpf.fileno(), old_mode)
                        except AttributeError:
                            pass
                    except Exception as e:
                        pass

                try:
                    tmpf.close()
                except Exception:
                    pass

                if old_mode is not None:
                    try:
                        os.chmod(tmpf.name, old_mode)
                    except Exception as e:
                        pass

                os.replace(tmpf.name, path)

                if old_atime is not None and old_mtime is not None:
                    try:
                        os.utime(path, (old_atime, old_mtime))
                    except Exception as e:
                        pass

                if old_mode is not None:
                    try:
                        os.chmod(path, old_mode)
                    except Exception as e:
                        pass

            except Exception:
                try:
                    if tmpf is not None:
                        tmp_name = tmpf.name
                        try:
                            tmpf.close()
                        except Exception:
                            pass
                        if os.path.exists(tmp_name):
                            try:
                                os.remove(tmp_name)
                            except Exception:
                                pass
                except Exception:
                    pass
                raise

        except Exception as e:
            logger.error("Failed to write file to disk: %s", path, exc_info=True)

    def _cleanup_thread(self, threads_list, thread_ref):
        try:
            if threads_list is None:
                return
            try:
                while thread_ref in threads_list:
                    threads_list.remove(thread_ref)
            except ValueError:
                pass
            try:
                threads_list[:] = [t for t in threads_list if not isdeleted(t) and t.isRunning()]
            except Exception:
                pass
        except Exception:
            pass

    def cleanup(self, timeout_ms=100):
        try:
            try:
                self.parent.text_loaders.remove(self.text_widget)
            except Exception:
                pass

            try:
                if self._current_path and hasattr(self.parent, "text_chunks"):
                    self.parent.text_chunks.pop(self._current_path, None)
            except Exception:
                pass

            self._cleanup_highlighter()

            try:
                if self.save_timer:
                    self.save_timer.stop()
                    self.save_timer = None
            except Exception:
                pass

            try:
                if self.search_debounce_timer:
                    self.search_debounce_timer.stop()
                    self.search_debounce_timer = None
            except Exception:
                pass

            try:
                if self.worker is not None:
                    try:
                        self.worker.finished.disconnect(self._on_finished)
                    except Exception:
                        try:
                            self.worker.finished.disconnect()
                        except Exception:
                            pass
                    try:
                        self.worker.parent = None
                    except Exception:
                        pass
            except Exception:
                pass

            try:
                if self.thread is not None:
                    try:
                        self.thread.quit()
                    except Exception:
                        pass
                    try:
                        self.thread.wait(timeout_ms)
                    except Exception:
                        pass
                    self.thread = None
            except Exception as e:
                pass

            try:
                tw = getattr(self, "text_widget", None)
                if tw is not None:
                    try:
                        tw.blockSignals(True)
                    except Exception:
                        pass
                    try:
                        tw.setPlainText("")
                        doc = tw.document()
                        if doc is not None:
                            try:
                                doc.clear()
                            except Exception:
                                pass
                    finally:
                        try:
                            tw.blockSignals(False)
                        except Exception:
                            pass
            except Exception:
                pass

            try:
                if hasattr(self, "_chunks") and self._chunks is not None:
                    try:
                        self._chunks.clear()
                    except Exception:
                        pass
                    self._chunks = None
            except Exception:
                pass

            try:
                self.worker = None
            except Exception:
                pass

        except Exception as e:
            pass

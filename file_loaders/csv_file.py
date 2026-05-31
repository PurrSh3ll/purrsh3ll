
import os
import codecs
import threading
import tempfile
import stat
import re

from PyQt6.sip import isdeleted
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QHBoxLayout, QTextEdit,
    QComboBox, QListView, QPushButton, QLineEdit, QCheckBox,
    QSizePolicy, QScrollArea, QApplication
)
from PyQt6.QtGui import QTextCharFormat, QColor, QTextCursor
from PyQt6.QtCore import QObject, QThread, pyqtSignal, pyqtSlot, Qt, QRegularExpression, QTimer

from gui.widgets.custom_line_edit import ExpandingLineEdit
from file_loaders.viewer_widgets import CustomTextEdit
from file_loaders.chunked_file_loader import ChunkedFileLoader

class Worker(QObject):
    finished = pyqtSignal(str, str)

    def __init__(self, file_path, chunk_size=256 * 1024, encoding="utf-8", errors="strict", parent=None):
        super().__init__()
        self.file_path = file_path
        self.chunk_size = int(chunk_size)
        self.encoding = encoding
        self.errors = errors
        self.parent = parent

    def run(self):
        try:
            chunks = []
            current_chunk_lines = []
            current_chunk_bytes = 0

            with open(self.file_path, "r", encoding=self.encoding, errors=self.errors) as f:
                for line in f:
                    line_bytes_len = len(line.encode(self.encoding, errors=self.errors))

                    if current_chunk_bytes == 0 and line_bytes_len >= self.chunk_size:
                        current_chunk_lines.append(line)
                        current_chunk_bytes += line_bytes_len

                        chunks.append("".join(current_chunk_lines))
                        current_chunk_lines = []
                        current_chunk_bytes = 0
                        continue

                    if current_chunk_bytes + line_bytes_len > self.chunk_size and current_chunk_lines:
                        chunks.append("".join(current_chunk_lines))
                        current_chunk_lines = []
                        current_chunk_bytes = 0

                    current_chunk_lines.append(line)
                    current_chunk_bytes += line_bytes_len

                if current_chunk_lines:
                    chunks.append("".join(current_chunk_lines))

            if self.parent is not None:
                if not hasattr(self.parent, "text_chunks"):
                    self.parent.text_chunks = {}
                self.parent.text_chunks[self.file_path] = chunks

            first_chunk = chunks[0] if chunks else ""
            self.finished.emit(self.file_path, first_chunk)

        except Exception as e:
            content = f"__ERROR__:{e}"
            self.finished.emit(self.file_path, content)

class _FinishedRelay(QObject):
    """Routes Worker.finished to Csv_file._on_finished in the main thread.

    Csv_file is not a QObject, so connecting worker.finished directly to
    self._on_finished uses DirectConnection — the slot runs in the worker
    thread and crashes with SIGSEGV when it modifies Qt UI objects.
    This relay is a QObject that lives in the main thread, so PyQt6
    automatically uses QueuedConnection for the cross-thread signal,
    ensuring _on_finished always runs in the main (GUI) thread.
    """

    def __init__(self, callback, parent=None):
        super().__init__(parent)
        self._cb = callback

    @pyqtSlot(str, str)
    def dispatch(self, path, content):
        self._cb(path, content)


class Csv_file(ChunkedFileLoader):
    def __init__(self):
        self.thread = None
        self.worker = None
        self.target_widget = None
        self.parent = None

    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        self.parent = parent
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(6, 6, 6, 6)

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

        scroll = QScrollArea(parent=parent.widgets['execution_tabs'])
        scroll.setWidgetResizable(True)
        scroll.setWidget(container)
        scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        th = QThread()
        self.thread = th
        self.worker = Worker(path, parent=parent)
        self.worker.moveToThread(th)

        th.started.connect(self.worker.run)

        # Route _on_finished through a QObject relay so it always runs in the
        # main thread. Csv_file is not a QObject — without the relay PyQt6
        # uses DirectConnection and _on_finished runs in the worker thread,
        # causing SIGSEGV when it modifies Qt UI objects.
        self._relay = _FinishedRelay(self._on_finished)
        self.worker.finished.connect(self._relay.dispatch)
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
            err_label = QLabel(f"\u26A0\uFE0F Error reading file:\n{err_text}", parent = self._loading_scroll)
            err_label.setWordWrap(True)
            err_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(err_label)
        else:
            control_bar_widget = QWidget(parent = self._loading_scroll)
            control_bar_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            control_bar_layout = QHBoxLayout(control_bar_widget)
            control_bar_layout.setContentsMargins(0, 0, 0, 0)
            control_bar_layout.setSpacing(6)

            zoom_out_btn = QPushButton("➖", parent= control_bar_widget)
            zoom_in_btn = QPushButton("➕", parent= control_bar_widget)
            edit_checkbox = QCheckBox("Edit", parent= control_bar_widget)
            zoom_out_btn.setFixedSize(28, 28)
            zoom_in_btn.setFixedSize(28, 28)

            control_bar_layout.addWidget(zoom_out_btn)
            control_bar_layout.addWidget(zoom_in_btn)
            control_bar_layout.addWidget(edit_checkbox)

            search_field = ExpandingLineEdit(parent= control_bar_widget)
            search_field.setPlaceholderText("Search...")

            search_field.setMinimumWidth(120)
            control_bar_layout.addWidget(search_field)

            method_box = QComboBox(parent= control_bar_widget)
            method_box.setView(QListView())

            method_box.addItems(["find", "replace", "regex", "replace regex"])

            control_bar_layout.addWidget(method_box)

            find_prev_btn = QPushButton("▲", parent= control_bar_widget)
            find_next_btn = QPushButton("▼", parent= control_bar_widget)
            find_prev_btn.setEnabled(False)
            find_next_btn.setEnabled(False)

            find_prev_btn.setFixedSize(28, 28)
            find_next_btn.setFixedSize(28, 28)
            find_prev_btn.setVisible(True)
            find_next_btn.setVisible(True)

            control_bar_layout.addWidget(find_prev_btn)
            control_bar_layout.addWidget(find_next_btn)

            replace_container = QWidget(parent= control_bar_widget)
            replace_layout = QHBoxLayout(replace_container)
            replace_layout.setContentsMargins(0, 0, 0, 0)
            replace_layout.setSpacing(6)

            replace_field = QLineEdit(parent= control_bar_widget)
            replace_field.setPlaceholderText("Replace with...")
            replace_field.setMinimumWidth(120)

            replace_btn = QPushButton("Replace", parent= control_bar_widget)

            def _on_replace_clicked():
                mode = method_box.currentText()
                if mode not in ("replace regex", "replace"):
                    return

                if not edit_checkbox.isChecked():
                    return

                needle = search_field.text()
                replacement = replace_field.text()

                if not needle:
                    return

                try:
                    full_text = self.text_widget.toPlainText()
                except Exception as e:
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
                    except re.error as e:
                        return

                elif mode == "replace regex":
                    lit = bool(literal_checkbox.isChecked())
                    try:
                        pat = QRegularExpression.escape(needle) if lit else needle
                        qre = QRegularExpression(pat)
                        qre.setPatternOptions(_qre_options_from_checks())

                        if not qre.isValid():
                            return

                        matches = []
                        it = qre.globalMatch(full_text)
                        while it.hasNext():
                            m = it.next()
                            s = m.capturedStart()
                            l = m.capturedLength()
                            if s >= 0 and l > 0:
                                matches.append((s, l))

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
                        try:
                            if _matches_store.get("positions"):
                                self.text_widget.setExtraSelections([])
                                _matches_store["shown"].clear()
                                _matches_store["positions"].clear()
                                _matches_store["total"] = 0
                        except Exception:
                            pass

                        self.text_widget.setPlainText(new_text)
                        last_saved["text"] = new_text
                    finally:
                        self.text_widget.blockSignals(False)
                        try:
                            self.text_widget.setUpdatesEnabled(True)
                        except Exception:
                            pass
                except Exception as e:
                    try:
                        self.text_widget.blockSignals(False)
                    except Exception:
                        pass

                try:
                    QTimer.singleShot(0, update_file_info)
                except Exception:
                    try:
                        update_file_info()
                    except Exception:
                        pass

                try:
                    idx = 0
                    try:
                        idx = nav_state.get("index", 0) if isinstance(nav_state, dict) else 0
                    except Exception:
                        idx = 0

                    try:
                        _ = chunks
                        chunks_exists = True
                    except NameError:
                        chunks_exists = False

                    if chunks_exists:
                        if idx >= len(chunks):
                            chunks.extend([""] * (idx - len(chunks) + 1))
                        chunks[idx] = new_text

                    if parent_ref is not None:
                        if not hasattr(parent_ref, "text_chunks"):
                            parent_ref.text_chunks = {}
                        parent_ref.text_chunks[path] = chunks if chunks_exists else [new_text]

                    try:
                        to_write = list(chunks) if chunks_exists else [new_text]
                        t = threading.Thread(target=self._write_chunks_to_disk, args=(to_write, path), daemon=True)
                        t.start()
                    except Exception as e:
                        pass

                except Exception as e:
                    pass

                try:
                    if search_field.text().strip():
                        self.search_debounce_timer.start()
                    else:
                        try:
                            self.search_debounce_timer.stop()
                        except Exception:
                            pass
                except Exception:
                    try:
                        _update_count_and_highlight(search_field.text())
                    except Exception:
                        pass

            replace_btn.clicked.connect(_on_replace_clicked)
            replace_layout.addWidget(replace_field)
            replace_layout.addWidget(replace_btn)

            control_bar_layout.addWidget(replace_container)

            replace_container.setVisible(False)
            options_btn = QPushButton("☰", parent= control_bar_widget)
            options_btn.setFixedSize(28, 28)
            control_bar_layout.addWidget(options_btn)

            count_label = QLabel("0 matches", parent= control_bar_widget)
            control_bar_layout.addWidget(count_label)

            def _copy_matches_to_clipboard():
                shown = _matches_store.get("shown", [])
                if not shown:
                    return
                text_to_copy = "\n".join(shown)
                try:
                    QApplication.clipboard().setText(text_to_copy)
                except Exception:
                    pass

            copy_matches_btn = QPushButton("Copy matches", parent= control_bar_widget)
            copy_matches_btn.clicked.connect(_copy_matches_to_clipboard)
            control_bar_layout.addWidget(copy_matches_btn)

            control_bar_layout.addStretch()
            layout.addWidget(control_bar_widget)

            def on_method_changed(text):

                replace_container.setVisible(text in ("replace", "replace regex"))

                is_search_mode = (text == "regex" or text == "find")
                find_prev_btn.setVisible(is_search_mode)
                find_next_btn.setVisible(is_search_mode)

                options_btn.setVisible(text != "find")

                if text == "find":
                    search_field.setPlaceholderText("Search...")
                    options_btn.hide()
                elif text == "replace":
                    search_field.setPlaceholderText("Search...")
                    options_btn.hide()
                elif text == "regex":
                    search_field.setPlaceholderText("Search (regex)...")
                    options_btn.show()
                elif text == "replace regex":
                    search_field.setPlaceholderText("Search (regex)...")
                    options_btn.show()

                if not is_search_mode:
                    nav_index["idx"] = -1

            method_box.currentTextChanged.connect(on_method_changed)

            flags_container = QWidget(parent= control_bar_widget)
            flags_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            flags_container.setMaximumHeight(36)
            flags_layout = QHBoxLayout(flags_container)
            flags_layout.setContentsMargins(0, 0, 0, 0)
            flags_layout.setSpacing(10)

            literal_checkbox = QCheckBox("LITERAL", parent = flags_container)
            flags_ignore = QCheckBox("IGNORECASE", parent = flags_container)
            flags_multiline = QCheckBox("MULTILINE", parent = flags_container)
            flags_dotall = QCheckBox("DOTALL", parent = flags_container)
            flags_verbose = QCheckBox("VERBOSE", parent = flags_container)

            for cb in (literal_checkbox, flags_ignore, flags_multiline, flags_dotall, flags_verbose):
                flags_layout.addWidget(cb)

            flags_layout.addStretch()
            layout.addWidget(flags_container)
            flags_container.setVisible(False)

            def toggle_flags():
                flags_container.setVisible(not flags_container.isVisible())

            options_btn.clicked.connect(toggle_flags)

            total_chunks = 0
            parent_ref = self.parent
            if parent_ref is not None and hasattr(parent_ref, "text_chunks"):
                chunks = parent_ref.text_chunks.get(path, [])
                if chunks:
                    total_chunks = len(chunks)

            if total_chunks == 0 and content:
                chunks = [content]
                total_chunks = 1

            nav_state = {"index": 0, "total": total_chunks}
            chunk_edit = None
            prev_btn = None
            next_btn = None
            total_label = None

            if total_chunks > 1:
                top_bar_widget = QWidget(parent= control_bar_widget)
                top_bar_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                top_bar_layout = QHBoxLayout(top_bar_widget)
                top_bar_layout.setContentsMargins(0, 0, 0, 0)
                top_bar_layout.setSpacing(6)

                prev_btn = QPushButton("◀", parent= top_bar_widget)
                next_btn = QPushButton("▶", parent= top_bar_widget)
                prev_btn.setFixedSize(28, 28)
                next_btn.setFixedSize(28, 28)

                chunk_edit = QLineEdit("1", parent= top_bar_widget)
                chunk_edit.setFixedWidth(40)
                total_label = QLabel(f"/{total_chunks} pages", parent= top_bar_widget)
                total_label.setEnabled(False)
                total_label.setStyleSheet("font-style: italic;")

                top_bar_layout.addWidget(prev_btn)
                top_bar_layout.addWidget(next_btn)
                top_bar_layout.addWidget(chunk_edit)
                top_bar_layout.addWidget(total_label)
                top_bar_layout.addStretch()
                layout.addWidget(top_bar_widget)

            self.text_widget = CustomTextEdit(self.parent)

            self.parent.text_loaders.append(self.text_widget)
            line_color = self.parent.qss_QPainter.get("painter_lines")
            self.text_widget.setStyleSheet(f"border-top: 2px solid {line_color}; border-bottom: none; "
                                      f"border-left: none; border-right: none;")
            self.text_widget.setReadOnly(True)
            self.text_widget.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
            self.text_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            layout.addWidget(self.text_widget)

            file_info_label = QLabel(parent= control_bar_widget)
            file_info_label.setStyleSheet("font-style: italic;")
            file_info_label.setText("File size: N/A | Lines: 0 | Characters: 0 | Permissions: N/A")
            file_info_label.setEnabled(False)
            layout.addWidget(file_info_label)

            def update_file_info():
                try:
                    try:
                        size = os.path.getsize(path)
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
                        st = os.stat(path)
                        permissions = stat.filemode(st.st_mode)
                    except Exception:
                        permissions = "N/A"

                    file_info_label.setText(
                        f"File size: {size_str} | Lines: {num_lines} | Characters: {num_chars} | Permissions: {permissions}"
                    )
                except Exception:
                    try:
                        file_info_label.setText("File size: N/A | Lines: 0 | Characters: 0 | Permissions: N/A")
                    except Exception:
                        pass

            self.text_widget.textChanged.connect(update_file_info)

            try:
                update_file_info()
            except Exception:
                pass

            zoom_state = {"level": 0}
            MIN_ZOOM = -10
            MAX_ZOOM = 40

            def _update_zoom_buttons():
                try:
                    zoom_out_btn.setEnabled(zoom_state["level"] > MIN_ZOOM)
                    zoom_in_btn.setEnabled(zoom_state["level"] < MAX_ZOOM)
                except Exception:
                    pass

            def _zoom_in():
                if zoom_state["level"] < MAX_ZOOM:
                    try:
                        self.text_widget.zoomIn(1)
                        zoom_state["level"] += 1
                    except Exception as e:
                        pass
                _update_zoom_buttons()

            def _zoom_out():
                if zoom_state["level"] > MIN_ZOOM:
                    try:
                        self.text_widget.zoomOut(1)
                        zoom_state["level"] -= 1
                    except Exception as e:
                        pass
                _update_zoom_buttons()

            zoom_in_btn.clicked.connect(_zoom_in)
            zoom_out_btn.clicked.connect(_zoom_out)

            _update_zoom_buttons()

            save_interval_ms = 1000
            self.save_timer = QTimer()
            self.save_timer.setSingleShot(True)
            self.save_timer.setInterval(save_interval_ms)

            last_saved = {"text": None}

            if 'chunks' not in locals():
                if parent_ref is not None and hasattr(parent_ref, "text_chunks"):
                    chunks = parent_ref.text_chunks.get(path, [])
                else:
                    chunks = [content] if content else []
                nav_state["total"] = len(chunks)

            def save_current_chunk():
                nonlocal chunks, nav_state, parent_ref, path, last_saved
                idx = nav_state["index"]
                new_text = self.text_widget.toPlainText()
                if last_saved["text"] == new_text:
                    return
                if idx >= len(chunks):
                    chunks.extend([""] * (idx - len(chunks) + 1))
                chunks[idx] = new_text
                last_saved["text"] = new_text
                if parent_ref is not None:
                    if not hasattr(parent_ref, "text_chunks"):
                        parent_ref.text_chunks = {}
                    parent_ref.text_chunks[path] = chunks

                try:
                    chunks_copy = list(chunks)
                    t = threading.Thread(target=self._write_chunks_to_disk, args=(chunks_copy, path), daemon=True)
                    t.start()
                except Exception:
                    pass

            def on_save_timer_timeout():
                save_current_chunk()

            self.save_timer.timeout.connect(on_save_timer_timeout)

            def on_text_changed():
                if not edit_checkbox.isChecked():
                    return
                current = self.text_widget.toPlainText()
                if last_saved["text"] != current:
                    self.save_timer.start()

            def on_edit_toggled(state):
                checked = bool(state)
                if checked:
                    self.text_widget.setReadOnly(False)
                    last_saved["text"] = self.text_widget.toPlainText()
                    self.save_timer.stop()
                    self.text_widget.setFocus()
                else:
                    self.text_widget.setReadOnly(True)
                    self.save_timer.stop()
                    save_current_chunk()

            self.text_widget.textChanged.connect(on_text_changed)
            edit_checkbox.stateChanged.connect(on_edit_toggled)

            if nav_state["total"] == 0:
                self.text_widget.setPlaceholderText("This file is empty.")
                self.text_widget.setPlainText("")
                last_saved["text"] = ""
            else:
                nav_state["index"] = 0

                if chunks:
                    self.text_widget.setPlainText(chunks[0])
                    last_saved["text"] = chunks[0]
                else:
                    self.text_widget.setPlainText(content or "")
                    last_saved["text"] = content or ""

            layout.addWidget(self.text_widget)

            max_matches = 10_000
            fmt_search = QTextCharFormat()
            fmt_search.setBackground(QColor("yellow"))

            searching_paused = {"val": False}

            def pause_search():
                searching_paused["val"] = True
                try:
                    self.search_debounce_timer.stop()
                except Exception:
                    pass

            def resume_search():
                searching_paused["val"] = False
                try:
                    if search_field.text().strip():
                        self.search_debounce_timer.start()
                    else:
                        self.search_debounce_timer.stop()
                except Exception:
                    pass

            def _qre_options_from_checks():
                opts = QRegularExpression.PatternOption(0)
                if flags_ignore.isChecked():
                    opts |= QRegularExpression.PatternOption.CaseInsensitiveOption
                if flags_multiline.isChecked():
                    opts |= QRegularExpression.PatternOption.MultilineOption
                if flags_dotall.isChecked():
                    opts |= QRegularExpression.PatternOption.DotMatchesEverythingOption
                if flags_verbose.isChecked():
                    opts |= QRegularExpression.PatternOption.ExtendedPatternSyntaxOption
                return opts

            _matches_store = {"shown": [], "positions": [], "total": 0}

            nav_index = {"idx": -1}

            def _select_match_at(idx):
                positions = _matches_store.get("positions", [])
                if not positions:
                    return
                if idx < 0 or idx >= len(positions):
                    return
                start, length = positions[idx]
                if start < 0 or length <= 0:
                    return
                cursor = QTextCursor(self.text_widget.document())
                cursor.setPosition(start)
                cursor.setPosition(start + length, QTextCursor.MoveMode.KeepAnchor)
                self.text_widget.setTextCursor(cursor)
                self.text_widget.setFocus()

            def _on_find_next():
                positions = _matches_store.get("positions", [])
                if not positions:
                    return
                if nav_index["idx"] < 0:
                    nav_index["idx"] = 0
                else:
                    nav_index["idx"] = (nav_index["idx"] + 1) % len(positions)
                _select_match_at(nav_index["idx"])

            def _on_find_prev():
                positions = _matches_store.get("positions", [])

                if not positions:
                    return

                if nav_index["idx"] < 0:
                    nav_index["idx"] = len(positions) - 1
                else:
                    nav_index["idx"] = (nav_index["idx"] - 1) % len(positions)
                _select_match_at(nav_index["idx"])

            find_next_btn.clicked.connect(_on_find_next)
            find_prev_btn.clicked.connect(_on_find_prev)

            def _update_count_and_highlight(txt):

                if searching_paused.get("val", False):
                    try:
                        self.text_widget.setExtraSelections([])
                    except Exception:
                        pass
                    count_label.setText("0 matches")
                    _matches_store["shown"] = []
                    _matches_store["positions"] = []
                    _matches_store["total"] = 0
                    find_prev_btn.setEnabled(False)
                    find_next_btn.setEnabled(False)
                    return

                lit = bool(literal_checkbox.isChecked())
                full_text = self.text_widget.toPlainText()
                method = method_box.currentText()

                nav_index["idx"] = -1

                if not txt:
                    self.text_widget.setExtraSelections([])
                    count_label.setText("0 matches")
                    _matches_store["shown"] = []
                    _matches_store["positions"] = []
                    _matches_store["total"] = 0
                    find_prev_btn.setEnabled(False)
                    find_next_btn.setEnabled(False)
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
                        while True:
                            if shown >= max_matches:
                                break
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
                        qre.setPatternOptions(_qre_options_from_checks())

                        if not qre.isValid():
                            self.text_widget.setExtraSelections([])
                            _matches_store["shown"] = []
                            _matches_store["positions"] = []
                            _matches_store["total"] = 0
                            nav_index["idx"] = -1
                            count_label.setText("0 matches")
                            find_prev_btn.setEnabled(False)
                            find_next_btn.setEnabled(False)
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
                    _matches_store["shown"] = shown_texts
                    _matches_store["positions"] = shown_positions
                    _matches_store["total"] = total

                    if total == max_matches:
                        count_label.setText(f"{max_matches} matches (reached max limit)")
                    else:
                        count_label.setText(f"{total} matches")

                    has_matches = total > 0
                    find_prev_btn.setEnabled(has_matches)
                    find_next_btn.setEnabled(has_matches)

                except Exception:
                    self.text_widget.setExtraSelections([])
                    _matches_store["shown"] = []
                    _matches_store["positions"] = []
                    _matches_store["total"] = 0
                    nav_index["idx"] = -1
                    count_label.setText("0 matches")
                    find_prev_btn.setEnabled(False)
                    find_next_btn.setEnabled(False)

            self.search_debounce_timer = QTimer()
            self.search_debounce_timer.setSingleShot(True)
            self.search_debounce_timer.setInterval(300)

            def _on_debounce_timeout():
                _update_count_and_highlight(search_field.text())

            search_field.textChanged.connect(lambda _=None: self.search_debounce_timer.start())

            for cb in (flags_ignore, flags_multiline, flags_dotall, flags_verbose):
                cb.stateChanged.connect(lambda _=None: self.search_debounce_timer.start())

            literal_checkbox.stateChanged.connect(lambda _=None: self.search_debounce_timer.start())

            self.search_debounce_timer.timeout.connect(_on_debounce_timeout)

            def try_remove_current_chunk_for_nav(direction):
                nonlocal chunks, nav_state, parent_ref, path, total_label, chunk_edit, prev_btn, next_btn, last_saved
                if self.text_widget.toPlainText() != "":
                    return False
                idx = nav_state["index"]
                if 0 <= idx < len(chunks):
                    del chunks[idx]
                    if parent_ref is not None:
                        if not hasattr(parent_ref, "text_chunks"):
                            parent_ref.text_chunks = {}
                        parent_ref.text_chunks[path] = chunks
                    try:
                        t = threading.Thread(target=self._write_chunks_to_disk, args=(list(chunks), path), daemon=True)
                        t.start()
                    except Exception:
                        pass
                    nav_state["total"] = len(chunks)
                    if nav_state["total"] == 0:
                        nav_state["index"] = 0
                        last_saved["text"] = ""
                    else:
                        if direction == 'prev':
                            nav_state["index"] = max(0, idx - 1)
                        else:
                            nav_state["index"] = max(0, min(idx, nav_state["total"] - 1))
                        last_saved["text"] = chunks[nav_state["index"]]

                    if total_label is not None:
                        total_label.setText(f"/{nav_state['total']} pages")
                    if chunk_edit is not None:
                        chunk_edit.setText(str(nav_state["index"] + 1) if nav_state["total"] > 0 else "0")
                    if prev_btn is not None:
                        prev_btn.setEnabled(nav_state["index"] > 0 and nav_state["total"] > 0)
                    if next_btn is not None:
                        next_btn.setEnabled(nav_state["index"] < (nav_state["total"] - 1))
                    return True
                return False

            if total_chunks > 1:
                def _clear_search_state_safe():
                    try:
                        try:
                            self.text_widget.setExtraSelections([])
                        except Exception:
                            pass
                        try:
                            _matches_store["shown"].clear()
                            _matches_store["positions"].clear()
                            _matches_store["total"] = 0
                        except Exception:
                            pass
                        try:
                            nav_index["idx"] = -1
                        except Exception:
                            pass
                        try:
                            count_label.setText("0 matches")
                            find_prev_btn.setEnabled(False)
                            find_next_btn.setEnabled(False)
                        except Exception:
                            pass
                    except Exception:
                        pass

                def on_prev():
                    nonlocal _matches_store, nav_index
                    pause_search()
                    try:
                        self.search_debounce_timer.stop()
                    except Exception:
                        pass

                    if search_field.text().strip():
                        _clear_search_state_safe()

                    if try_remove_current_chunk_for_nav('prev'):
                        update_view()
                        if search_field.text().strip():
                            QTimer.singleShot(0, resume_search)
                        else:
                            searching_paused["val"] = False
                        return

                    if edit_checkbox.isChecked():
                        self.save_timer.stop()
                        save_current_chunk()

                    nav_state["index"] = max(0, nav_state["index"] - 1)
                    update_view()

                    if search_field.text().strip():
                        QTimer.singleShot(0, resume_search)
                    else:
                        searching_paused["val"] = False

                def on_next():
                    nonlocal _matches_store, nav_index
                    pause_search()
                    try:
                        self.search_debounce_timer.stop()
                    except Exception:
                        pass

                    if search_field.text().strip():
                        _clear_search_state_safe()

                    if try_remove_current_chunk_for_nav('next'):
                        update_view()
                        if search_field.text().strip():
                            QTimer.singleShot(0, resume_search)
                        else:
                            searching_paused["val"] = False
                        return

                    if edit_checkbox.isChecked():
                        self.save_timer.stop()
                        save_current_chunk()

                    nav_state["index"] = min(nav_state["total"] - 1, nav_state["index"] + 1)
                    update_view()

                    if search_field.text().strip():
                        QTimer.singleShot(0, resume_search)
                    else:
                        searching_paused["val"] = False

                prev_btn.clicked.connect(on_prev)
                next_btn.clicked.connect(on_next)

                def on_chunk_edit_entered():
                    txt = chunk_edit.text().strip()
                    try:
                        n = int(txt)
                        if n < 1:
                            n = 1
                        if n > nav_state["total"]:
                            n = nav_state["total"]
                        if try_remove_current_chunk_for_nav('next'):
                            update_view()
                            return
                        if edit_checkbox.isChecked():
                            self.save_timer.stop()
                            save_current_chunk()
                        nav_state["index"] = n - 1
                        update_view()
                    except Exception:
                        chunk_edit.setText(str(nav_state["index"] + 1))

                chunk_edit.returnPressed.connect(on_chunk_edit_entered)

            def update_view():
                nonlocal nav_state, chunk_edit, prev_btn, next_btn, parent_ref, path, chunks, total_label

                if parent_ref is not None and hasattr(parent_ref, "text_chunks"):
                    chunks_local = list(parent_ref.text_chunks.get(path, chunks if 'chunks' in locals() else []))
                else:
                    chunks_local = list(chunks if 'chunks' in locals() else [])

                nav_state["total"] = len(chunks_local)
                idx = nav_state.get("index", 0)

                try:
                    if not search_field.text().strip():
                        _clear_search_state_safe()
                except Exception:
                    pass

                if not chunks_local:
                    try:
                        self.text_widget.setExtraSelections([])
                    except Exception:
                        pass

                    self.text_widget.blockSignals(True)
                    try:
                        try:
                            if self.text_widget.toPlainText() != "":
                                self.text_widget.setPlainText("")
                        except Exception:
                            self.text_widget.setPlainText("")
                        last_saved["text"] = ""
                    finally:
                        self.text_widget.blockSignals(False)
                else:
                    idx = max(0, min(idx, len(chunks_local) - 1))
                    nav_state["index"] = idx

                    current_content = chunks_local[idx]

                    try:
                        self.text_widget.setExtraSelections([])
                    except Exception:
                        pass

                    self.text_widget.blockSignals(True)
                    try:
                        try:
                            current_on_widget = self.text_widget.toPlainText()
                        except Exception:
                            current_on_widget = None

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

                        last_saved["text"] = current_content
                    finally:
                        self.text_widget.blockSignals(False)

                    try:
                        QTimer.singleShot(0, update_file_info)
                    except Exception:
                        try:
                            update_file_info()
                        except Exception:
                            pass

                if chunk_edit is not None:
                    chunk_edit.setText(str(nav_state["index"] + 1) if nav_state["total"] > 0 else "0")
                if total_label is not None:
                    total_label.setText(f"/{nav_state['total']} pages")
                if prev_btn is not None:
                    prev_btn.setEnabled(nav_state["index"] > 0 and nav_state["total"] > 0)
                if next_btn is not None:
                    next_btn.setEnabled(nav_state["index"] < (nav_state["total"] - 1))

            if total_chunks > 1:
                update_view()


    def cleanup(self, timeout_ms=100):
        try:
            self.parent.text_loaders.remove(self.text_widget)
            try:
                if hasattr(self, "save_timer") and self.save_timer:
                    try:
                        self.save_timer.stop()
                    except Exception:
                        pass
                    self.save_timer = None
            except Exception:
                pass

            try:
                if hasattr(self, "search_debounce_timer") and self.search_debounce_timer:
                    try:
                        self.search_debounce_timer.stop()
                    except Exception:
                        pass
                    self.search_debounce_timer = None
            except Exception:
                pass

            try:
                if hasattr(self, "worker") and self.worker is not None:
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
                if hasattr(self, "thread") and self.thread is not None:
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
                if hasattr(self, "chunks"):
                    try:
                        self.chunks.clear()
                    except Exception:
                        pass
                    self.chunks = None
            except Exception:
                pass

            try:
                if hasattr(self, "worker"):
                    try:
                        self.worker = None
                    except Exception:
                        pass
            except Exception:
                pass

        except Exception as e:
            pass


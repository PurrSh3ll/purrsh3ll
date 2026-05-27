
import os
import codecs
import threading
import tempfile
import stat
import re
import webbrowser
from pathlib import Path
from urllib.parse import unquote

from PyQt6.sip import isdeleted
from file_loaders.base_file_loader import _store_chunks
from PyQt6.QtWidgets import (
    QWidget, QLabel, QHBoxLayout, QVBoxLayout, QSizePolicy,
    QScrollArea, QComboBox, QListView, QPushButton, QLineEdit,
    QCheckBox, QTextEdit, QApplication, QSplitter, QTextBrowser,
    QButtonGroup, QMenu, QMessageBox, QToolTip
)
from PyQt6.QtCore import Qt, QObject, QThread, QTimer, QUrl, QRegularExpression, QEvent, QSizeF
from PyQt6.QtGui import QTextCharFormat, QColor, QTextCursor, QCursor, QDesktopServices, QAction, QTextImageFormat, QImage

from gui.widgets.custom_line_edit import ExpandingLineEdit
from file_loaders.viewer_widgets import Worker, LineNumberArea, TextEditWithLineNumbers
from file_loaders.chunked_file_loader import ChunkedFileLoader


class _ZoomEventFilter(QObject):
    """Intercepts Ctrl+Scroll on a widget's viewport and routes it through
    the provided zoom callbacks, consuming the event so the widget's own
    wheelEvent does not fire a second time.
    Also intercepts Resize events on the preview widget itself and triggers
    a debounced rescale so images always fill the preview pane width."""

    def __init__(self, on_zoom_in, on_zoom_out, on_resize=None, parent=None):
        super().__init__(parent)
        self._on_zoom_in = on_zoom_in
        self._on_zoom_out = on_zoom_out
        self._on_resize = on_resize
        self._resize_timer = QTimer()
        self._resize_timer.setSingleShot(True)
        self._resize_timer.setInterval(60)
        if on_resize:
            self._resize_timer.timeout.connect(on_resize)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.Wheel:
            if QApplication.keyboardModifiers() & Qt.KeyboardModifier.ControlModifier:
                if event.angleDelta().y() > 0:
                    self._on_zoom_in()
                elif event.angleDelta().y() < 0:
                    self._on_zoom_out()
                return True
        if event.type() in (QEvent.Type.Resize, QEvent.Type.Show) and self._on_resize:
            self._resize_timer.start()
        return False


class Markdown_file(ChunkedFileLoader):
    def __init__(self):
        self.thread = None
        self.worker = None
        self.target_widget = None

    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        self._controller = parent
        self.qss_QMessagebox_style = parent.messagebox_stylesheet
        self.parent = parent
        self.path = path
        self.base_dir = Path(self.path).parent
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
        self.worker = Worker(path, parent=parent)
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

                    _store_chunks(parent_ref, path, chunks if chunks_exists else [new_text])

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

            BTN_SIZE = 30

            def _reset_splitter():
                self.left_container.show()
                self.right_container.show()
                self.splitter.handle(1).setEnabled(True)
                self.splitter.setHandleWidth(5)

            def on_editor_view_clicked():
                _reset_splitter()

                self.right_container.hide()
                self.splitter.setStretchFactor(0, 1)
                self.splitter.setStretchFactor(1, 0)
                self.splitter.setSizes([1, 0])

            def on_side_by_side_clicked():
                _reset_splitter()

                self.splitter.setStretchFactor(0, 1)
                self.splitter.setStretchFactor(1, 2)
                self.splitter.setSizes([800, 400])

            def on_reading_view_clicked():
                _reset_splitter()

                self.left_container.hide()
                self.splitter.setStretchFactor(0, 0)
                self.splitter.setStretchFactor(1, 1)
                self.splitter.setSizes([0, 1])

            editor_view_btn = QPushButton("</>", parent=control_bar_widget)
            editor_view_btn.setFixedSize(BTN_SIZE, BTN_SIZE)
            editor_view_btn.setToolTip("Editor View")
            editor_view_btn.setCheckable(True)
            editor_view_btn.clicked.connect(on_editor_view_clicked)

            side_by_side_btn = QPushButton("◫", parent=control_bar_widget)
            side_by_side_btn.setFixedSize(BTN_SIZE, BTN_SIZE)
            side_by_side_btn.setToolTip("Side-by-Side View")
            side_by_side_btn.setCheckable(True)
            side_by_side_btn.clicked.connect(on_side_by_side_clicked)

            reading_view_btn = QPushButton("≡", parent=control_bar_widget)
            reading_view_btn.setFixedSize(BTN_SIZE, BTN_SIZE)
            reading_view_btn.setToolTip("Reading View")
            reading_view_btn.setCheckable(True)
            reading_view_btn.clicked.connect(on_reading_view_clicked)

            view_button_group = QButtonGroup(control_bar_widget)
            view_button_group.setExclusive(True)

            view_button_group.addButton(editor_view_btn)
            view_button_group.addButton(side_by_side_btn)
            view_button_group.addButton(reading_view_btn)

            reading_view_btn.setChecked(True)

            control_bar_layout.addWidget(editor_view_btn)
            control_bar_layout.addWidget(side_by_side_btn)
            control_bar_layout.addWidget(reading_view_btn)

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
            parent_ref = getattr(self.worker, "parent", None)
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
                total_label = QLabel(f"/{total_chunks} pages", parent=top_bar_widget)
                total_label.setEnabled(False)
                total_label.setStyleSheet("font-style: italic;")

                top_bar_layout.addWidget(prev_btn)
                top_bar_layout.addWidget(next_btn)
                top_bar_layout.addWidget(chunk_edit)
                top_bar_layout.addWidget(total_label)
                top_bar_layout.addStretch()
                layout.addWidget(top_bar_widget)

            border_line = self._controller.qss_QPainter.get("painter_lines", "#2B2D30")

            def _create_text_widget():
                tw = TextEditWithLineNumbers(controller=self.parent, parent=self._loading_scroll)
                tw.setObjectName("text_edit_line_numb")
                tw.setReadOnly(True)
                tw.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
                self._controller.text_loaders.append(tw)
                return tw

            def _create_content_area():
                content = QWidget(parent=self._loading_scroll)
                content.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
                layout_ca = QHBoxLayout(content)
                layout_ca.setContentsMargins(0, 0, 0, 0)
                layout_ca.setSpacing(0)
                return content, layout_ca

            def _create_splitter(parent_widget):
                s = QSplitter(Qt.Orientation.Horizontal, parent_widget)
                s.setChildrenCollapsible(True)
                return s

            def _wrap_in_container(widget, parent_widget):
                container = QWidget(parent_widget)
                layout = QVBoxLayout(container)
                layout.setContentsMargins(0, 0, 0, 0)
                layout.setSpacing(0)
                layout.addWidget(widget)
                return container

            def _set_ignored_size_policy(*widgets):
                for w in widgets:
                    w.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Expanding)

            def _add_info_labels():
                file_info_label = QLabel(parent=control_bar_widget)
                file_info_label.setStyleSheet("font-style: italic;")
                file_info_label.setText("File size: N/A | Lines: 0 | Characters: 0 | Permissions: N/A")
                file_info_label.setEnabled(False)
                layout.addWidget(file_info_label)

            self.text_widget = _create_text_widget()

            self.content_area, content_area_layout = _create_content_area()
            self.splitter = _create_splitter(self.content_area)

            self.left_container = _wrap_in_container(self.text_widget, self.content_area)
            self.splitter.addWidget(self.left_container)

            preview_widget = None

            preview_widget = QTextBrowser(self.content_area)
            preview_widget.setReadOnly(True)
            preview_widget.document().setDocumentMargin(20)

            preview_widget.setOpenLinks(False)
            preview_widget.setOpenExternalLinks(False)

            def _show_path_not_found_tooltip(path: str):
                QToolTip.showText(
                    QCursor.pos(),
                    f"Path does not exist:\n{path}"
                )
                QTimer.singleShot(2500, QToolTip.hideText)

            def _invalid_theme_tooltip(theme: str):
                QToolTip.showText(
                    QCursor.pos(),
                    f"Invalid theme name:\n{theme}"
                )
                QTimer.singleShot(2500, QToolTip.hideText)

            def _print_action(url: QUrl):
                category = url.host()

                path = url.path().lstrip("/")
                parts = path.split("/", 1)

                action_type = parts[0] if len(parts) > 0 else ""
                payload = unquote(parts[1]) if len(parts) > 1 else ""

                if category == "run" and action_type == "command":

                    terminal_tabs = self.parent.widgets["terminal_tabs"]

                    self.parent.console_args = {"command": payload}
                    self.parent.widgets["btn_add_console"].click()
                    self.parent.console_args.clear()

                    last_idx = terminal_tabs.count() - 1
                    if last_idx >= 0:
                        terminal_tabs.setCurrentIndex(last_idx)
                elif category == "change" and action_type == "theme":
                    if payload in self.parent.themes:
                        self.parent.change_actual_theme(payload)
                    else:
                        _invalid_theme_tooltip(payload)
                else:
                    pass

            def on_link_clicked(url: QUrl):
                url_str = url.toString()
                scheme = url.scheme()

                if scheme == "action":
                    _print_action(url)
                    return

                if scheme in ("http", "https"):
                    QDesktopServices.openUrl(url)
                    return

                if scheme == "file" or url.isLocalFile():
                    local_path = Path(url.toLocalFile())

                    if local_path.exists():
                        if local_path.is_dir():
                            QDesktopServices.openUrl(QUrl.fromLocalFile(str(local_path)))
                        else:
                            self.parent.open_new_tab_for_terminal(file = str(local_path))

                        return

                    _show_path_not_found_tooltip(str(local_path))
                    return

                resolved_path = (self.base_dir / url_str).resolve()

                if resolved_path.exists():
                    if resolved_path.is_dir():
                        QDesktopServices.openUrl(QUrl.fromLocalFile(str(resolved_path)))
                    else:
                        self.parent.open_new_tab_for_terminal(file=str(resolved_path))
                    return

                _show_path_not_found_tooltip(str(resolved_path))

            preview_widget.anchorClicked.connect(on_link_clicked)

            zoom_state = {"level": 0}
            MIN_ZOOM = -10
            MAX_ZOOM = 40
            _img_natural_sizes = {}

            def _rescale_images():
                if preview_widget is None:
                    return
                full_viewport_w = preview_widget.viewport().width()
                if full_viewport_w <= 0:
                    return
                doc_margin = int(preview_widget.document().documentMargin())
                viewport_w = full_viewport_w - 2 * doc_margin
                doc = preview_widget.document()

                # Collect changes first, apply after — avoids iterator invalidation
                changes = []
                block = doc.begin()
                while block.isValid():
                    it = block.begin()
                    while not it.atEnd():
                        frag = it.fragment()
                        fmt = frag.charFormat()
                        if fmt.isImageFormat():
                            img_fmt = fmt.toImageFormat()
                            name = img_fmt.name()
                            img_path = unquote(name)
                            if not os.path.isabs(img_path):
                                img_path = str(self.base_dir / img_path)
                            if img_path not in _img_natural_sizes:
                                qimg = QImage(img_path)
                                if not qimg.isNull():
                                    _img_natural_sizes[img_path] = (qimg.width(), qimg.height())
                            if img_path in _img_natural_sizes:
                                nat_w, nat_h = _img_natural_sizes[img_path]
                                target_w = min(nat_w, max(1, viewport_w))
                                target_h = int(target_w * nat_h / nat_w) if nat_w > 0 else target_w
                                changes.append((frag.position(), frag.length(), name, target_w, target_h))
                        it += 1
                    block = block.next()

                for pos, length, name, w, h in changes:
                    new_fmt = QTextImageFormat()
                    new_fmt.setName(name)
                    new_fmt.setWidth(w)
                    new_fmt.setHeight(h)
                    c = QTextCursor(doc)
                    c.setPosition(pos)
                    c.setPosition(pos + length, QTextCursor.MoveMode.KeepAnchor)
                    c.setCharFormat(new_fmt)

                # Force document reflow at the correct viewport width —
                # equivalent to what QTextEdit::resizeEvent does internally
                doc.setPageSize(QSizeF(full_viewport_w, -1))

            def update_preview():
                text = self.text_widget.toPlainText()

                doc = preview_widget.document()
                doc.setBaseUrl(QUrl.fromLocalFile(str(self.base_dir) + "/"))

                preview_widget.setMarkdown(text if text.strip() else "")
                QTimer.singleShot(0, _rescale_images)

            self.text_widget.textChanged.connect(update_preview)

            update_preview()

            self.right_container = _wrap_in_container(preview_widget, self.content_area)
            self.splitter.addWidget(self.right_container)

            self.splitter.setStretchFactor(0, 1)
            self.splitter.setStretchFactor(1, 2)
            self.splitter.setSizes([800, 400])
            self.left_container.setMinimumWidth(15)
            self.right_container.setMinimumWidth(15)

            _set_ignored_size_policy(self.text_widget, self.left_container, preview_widget, self.right_container)

            content_area_layout.addWidget(self.splitter)

            on_reading_view_clicked()

            file_info_label = QLabel(parent=control_bar_widget)
            file_info_label.setStyleSheet("font-style: italic;")
            file_info_label.setText("File size: N/A | Lines: 0 | Characters: 0 | Permissions: N/A")
            file_info_label.setEnabled(False)
            layout.addWidget(file_info_label)

            layout.addWidget(self.content_area)

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
                        if preview_widget is not None:
                            preview_widget.zoomIn(1)
                        zoom_state["level"] += 1
                        QTimer.singleShot(0, _rescale_images)
                    except Exception as e:
                        pass
                _update_zoom_buttons()

            def _zoom_out():
                if zoom_state["level"] > MIN_ZOOM:
                    try:
                        self.text_widget.zoomOut(1)
                        if preview_widget is not None:
                            preview_widget.zoomOut(1)
                        zoom_state["level"] -= 1
                        QTimer.singleShot(0, _rescale_images)
                    except Exception as e:
                        pass
                _update_zoom_buttons()

            zoom_in_btn.clicked.connect(_zoom_in)
            zoom_out_btn.clicked.connect(_zoom_out)

            _zoom_filter = _ZoomEventFilter(_zoom_in, _zoom_out, on_resize=_rescale_images)
            self.text_widget.viewport().installEventFilter(_zoom_filter)
            preview_widget.viewport().installEventFilter(_zoom_filter)
            preview_widget.installEventFilter(_zoom_filter)
            self._zoom_filter = _zoom_filter
            QTimer.singleShot(0, _rescale_images)

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
                _store_chunks(parent_ref, path, chunks)

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
                    _store_chunks(parent_ref, path, chunks)
                    try:
                        t = threading.Thread(target=self._write_chunks_to_disk, args=(list(chunks), path),
                                             daemon=True)
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

        if self.thread is not None:
            self.thread.quit()

    def cleanup(self, timeout_ms=100):
        try:
            try:
                if hasattr(self, "_controller") and getattr(self._controller, "text_loaders", None) is not None:
                    try:
                        if getattr(self, "text_widget", None) in self._controller.text_loaders:
                            self._controller.text_loaders.remove(self.text_widget)
                    except Exception:
                        pass

            except Exception:
                pass

            try:
                tw = getattr(self, "text_widget", None)
                if tw is not None:
                    try:
                        try:
                            tw.textChanged.disconnect()
                        except Exception:
                            pass
                    except Exception:
                        pass
            except Exception:
                pass

            try:
                if hasattr(self, "_preview_timer") and self._preview_timer is not None:
                    try:
                        self._preview_timer.stop()
                    except Exception:
                        pass
                    try:
                        self._preview_timer.timeout.disconnect()
                    except Exception:
                        pass
                    try:
                        self._preview_timer.deleteLater()
                    except Exception:
                        pass
                    self._preview_timer = None
            except Exception:
                pass

            for tname in ("save_timer", "search_debounce_timer"):
                try:
                    timer = getattr(self, tname, None)
                    if timer:
                        try:
                            timer.stop()
                        except Exception:
                            pass
                        try:
                            timer.timeout.disconnect()
                        except Exception:
                            pass
                        try:
                            timer.deleteLater()
                        except Exception:
                            pass
                        setattr(self, tname, None)
                except Exception:
                    pass

            try:
                worker = getattr(self, "worker", None)
                if worker is not None:
                    try:
                        try:
                            worker.finished.disconnect(self._on_finished)
                        except Exception:
                            try:
                                worker.finished.disconnect()
                            except Exception:
                                pass
                    except Exception:
                        pass
                    try:
                        worker.setParent(None)
                    except Exception:
                        pass
                    try:
                        self.worker = None
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
                    try:
                        self.thread = None
                    except Exception:
                        pass
            except Exception:
                pass

            try:
                if hasattr(self, "syntax_highlighter") and getattr(self, "syntax_highlighter") is not None:
                    try:
                        try:
                            self.syntax_highlighter.setDocument(None)
                        except Exception:
                            pass
                    except Exception:
                        pass
                    try:
                        del self.syntax_highlighter
                    except Exception:
                        try:
                            self.syntax_highlighter = None
                        except Exception:
                            pass
            except Exception:
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
                    except Exception:
                        pass
                    try:
                        doc = tw.document()
                        if doc is not None:
                            try:
                                doc.clear()
                            except Exception:
                                pass
                    except Exception:
                        pass
                    try:
                        tw.blockSignals(False)
                    except Exception:
                        pass

                    try:
                        tw.setParent(None)
                    except Exception:
                        pass
                    try:
                        tw.deleteLater()
                    except Exception:
                        pass
                    try:
                        del self.text_widget
                    except Exception:
                        try:
                            self.text_widget = None
                        except Exception:
                            pass
            except Exception:
                pass

            try:
                preview = getattr(self, "preview", None)
                if preview is not None:
                    try:
                        try:
                            preview.stop()
                        except Exception:
                            pass
                        try:
                            preview.setMarkdown("")
                        except Exception:
                            pass
                        try:
                            preview.deleteLater()
                        except Exception:
                            pass
                        try:
                            self.preview = None
                        except Exception:
                            pass
                    except Exception:
                        pass
                else:
                    try:
                        pv = locals().get("preview_widget", None)
                        if pv is not None:
                            try:
                                pv.deleteLater()
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                pass

            try:
                try:
                    self.viewport().removeEventFilter(self)
                except Exception:
                    pass
            except Exception:
                pass

            try:
                if hasattr(self, "chunks") and self.chunks is not None:
                    try:
                        self.chunks.clear()
                    except Exception:
                        pass
                    self.chunks = None
            except Exception:
                pass

            try:
                for attr in ("worker", "thread", "syntax_highlighter", "text_widget", "preview"):
                    try:
                        if hasattr(self, attr):
                            try:
                                setattr(self, attr, None)
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                pass

        except Exception as e:
            pass


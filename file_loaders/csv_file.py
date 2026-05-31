
import csv
import io
import os
import stat
import threading
import re

from PyQt6.sip import isdeleted
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QHBoxLayout, QTextEdit,
    QComboBox, QListView, QPushButton, QLineEdit, QCheckBox,
    QSizePolicy, QScrollArea, QApplication, QTableView,
    QAbstractItemView, QHeaderView,
)
from PyQt6.QtGui import QTextCharFormat, QColor, QTextCursor, QBrush
from PyQt6.QtCore import (
    QObject, QThread, pyqtSignal, pyqtSlot, Qt,
    QTimer, QAbstractTableModel, QModelIndex,
)

from gui.widgets.custom_line_edit import ExpandingLineEdit
from file_loaders.viewer_widgets import CustomTextEdit
from file_loaders.chunked_file_loader import ChunkedFileLoader

ROWS_PER_PAGE = 2000


# ── Model ──────────────────────────────────────────────────────────────────────

class CsvTableModel(QAbstractTableModel):
    """Displays a page of CSV rows backed by a shared all_rows list."""

    def __init__(self, headers, all_rows, parent=None):
        super().__init__(parent)
        self._headers = headers
        self._all_rows = all_rows
        self._page_start = 0
        self._page_end = min(ROWS_PER_PAGE, len(all_rows))
        self._editable = False
        self._search_text = ""
        self._highlight = QBrush(QColor("#ffeb3b"))

    # ── QAbstractTableModel interface ──────────────────────────────────────

    def rowCount(self, parent=QModelIndex()):
        return self._page_end - self._page_start

    def columnCount(self, parent=QModelIndex()):
        return len(self._headers)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        abs_row = self._page_start + index.row()
        col = index.column()
        if not (0 <= abs_row < len(self._all_rows)):
            return None
        row = self._all_rows[abs_row]
        cell = row[col] if col < len(row) else ""
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole):
            return cell
        if role == Qt.ItemDataRole.BackgroundRole and self._search_text:
            if self._search_text.lower() in cell.lower():
                return self._highlight
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self._headers[section] if section < len(self._headers) else str(section + 1)
        return str(self._page_start + section + 1)

    def flags(self, index):
        f = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if self._editable:
            f |= Qt.ItemFlag.ItemIsEditable
        return f

    def setData(self, index, value, role=Qt.ItemDataRole.EditRole):
        if role != Qt.ItemDataRole.EditRole or not index.isValid():
            return False
        abs_row = self._page_start + index.row()
        col = index.column()
        if 0 <= abs_row < len(self._all_rows):
            row = self._all_rows[abs_row]
            while len(row) <= col:
                row.append("")
            row[col] = str(value) if value is not None else ""
            self.dataChanged.emit(index, index, [role])
            return True
        return False

    # ── Helpers ────────────────────────────────────────────────────────────

    def set_page(self, start):
        self.beginResetModel()
        self._page_start = start
        self._page_end = min(start + ROWS_PER_PAGE, len(self._all_rows))
        self.endResetModel()

    def reset_data(self, headers, all_rows):
        self.beginResetModel()
        self._headers = headers
        self._all_rows = all_rows
        self._page_start = 0
        self._page_end = min(ROWS_PER_PAGE, len(all_rows))
        self.endResetModel()

    def set_editable(self, editable):
        self._editable = editable
        if self.rowCount() > 0 and self.columnCount() > 0:
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(self.rowCount() - 1, self.columnCount() - 1),
            )

    def set_search(self, text):
        self._search_text = text
        if self.rowCount() > 0 and self.columnCount() > 0:
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(self.rowCount() - 1, self.columnCount() - 1),
                [Qt.ItemDataRole.BackgroundRole],
            )

    def page_matches(self, text):
        """(row_on_page, col) pairs matching text within the current page."""
        if not text:
            return []
        tl = text.lower()
        result = []
        for r in range(self._page_start, self._page_end):
            for c, cell in enumerate(self._all_rows[r]):
                if tl in cell.lower():
                    result.append((r - self._page_start, c))
        return result

    def total_matches(self, text):
        if not text:
            return 0
        tl = text.lower()
        return sum(1 for row in self._all_rows for cell in row if tl in cell.lower())


# ── Worker ─────────────────────────────────────────────────────────────────────

class _FinishedRelay(QObject):
    def __init__(self, callback, parent=None):
        super().__init__(parent)
        self._cb = callback

    @pyqtSlot(str, object)
    def dispatch(self, path, data):
        self._cb(path, data)


class Worker(QObject):
    finished = pyqtSignal(str, object)

    _SEP_MAP = {"auto": None, ",": ",", ";": ";", "tab": "\t", "|": "|"}

    def __init__(self, file_path, separator="auto", has_header=True, parent_obj=None):
        super().__init__()
        self.file_path = file_path
        self.separator = separator
        self.has_header = has_header
        self.parent_obj = parent_obj

    def run(self):
        try:
            # Try encodings in order
            raw_text = None
            for enc in ("utf-8-sig", "utf-8", "latin-1"):
                try:
                    with open(self.file_path, "r", encoding=enc, errors="strict") as f:
                        raw_text = f.read()
                    break
                except (UnicodeDecodeError, LookupError):
                    continue
            if raw_text is None:
                with open(self.file_path, "r", encoding="latin-1", errors="replace") as f:
                    raw_text = f.read()

            # Detect separator
            sep = self._SEP_MAP.get(self.separator)
            if sep is None:
                try:
                    dialect = csv.Sniffer().sniff(raw_text[:8192], delimiters=",;\t|")
                    sep = dialect.delimiter
                except Exception:
                    sep = ","

            # Parse CSV
            rows = list(csv.reader(io.StringIO(raw_text), delimiter=sep))

            if rows and self.has_header:
                headers = rows[0]
                data_rows = rows[1:]
            elif rows:
                headers = [f"Col {i + 1}" for i in range(len(rows[0]))]
                data_rows = rows
            else:
                headers = []
                data_rows = []

            ncols = len(headers)
            for r in data_rows:
                if len(r) < ncols:
                    r.extend([""] * (ncols - len(r)))

            result = {
                "error": None,
                "headers": headers,
                "all_rows": data_rows,
                "total_rows": len(data_rows),
                "separator": sep,
                "has_header": self.has_header,
                "raw_text": raw_text,
            }

            if self.parent_obj is not None:
                if not hasattr(self.parent_obj, "csv_data"):
                    self.parent_obj.csv_data = {}
                self.parent_obj.csv_data[self.file_path] = result

            self.finished.emit(self.file_path, result)

        except Exception as e:
            self.finished.emit(self.file_path, {"error": str(e)})


# ── Main loader ────────────────────────────────────────────────────────────────

class Csv_file(ChunkedFileLoader):

    def __init__(self):
        self.thread = None
        self.worker = None
        self.target_widget = None
        self.parent = None
        self._table_model = None
        self.text_widget = None

    # ── load_file ──────────────────────────────────────────────────────────

    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        self.parent = parent

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(6, 6, 6, 6)

        file_name = os.path.basename(path)
        label = QLabel(f"⏳ Loading {file_name} ...")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setWordWrap(True)

        wrapper = QWidget()
        w_layout = QHBoxLayout(wrapper)
        w_layout.setContentsMargins(0, 0, 0, 0)
        w_layout.addStretch(1)
        w_layout.addWidget(label)
        w_layout.addStretch(1)
        wrapper.setMaximumWidth(400)

        layout.addWidget(wrapper, alignment=Qt.AlignmentFlag.AlignCenter)

        self.target_widget = container if target_widget is None else target_widget

        scroll = QScrollArea(parent=parent.widgets['execution_tabs'])
        scroll.setWidgetResizable(True)
        scroll.setWidget(container)
        scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        th = QThread()
        self.thread = th
        self.worker = Worker(file_path=path, parent_obj=parent)
        self.worker.moveToThread(th)

        th.started.connect(self.worker.run)

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

        self._loading_scroll = scroll
        return scroll

    # ── _on_finished ───────────────────────────────────────────────────────

    def _on_finished(self, path, data):
        if self.target_widget is None or isdeleted(self.target_widget):
            return
        layout = self.target_widget.layout()
        if layout is None:
            return

        # Remove loading spinner
        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        if data.get("error"):
            err = QLabel(f"⚠️ Error reading file:\n{data['error']}")
            err.setWordWrap(True)
            err.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(err)
            return

        # ── State ──────────────────────────────────────────────────────────
        csv_state = {
            "headers":    data["headers"],
            "all_rows":   data["all_rows"],
            "separator":  data["separator"],
            "has_header": data["has_header"],
        }
        raw_text = data["raw_text"]
        total_rows = data["total_rows"]
        ncols = len(csv_state["headers"])

        total_pages = max(1, (total_rows + ROWS_PER_PAGE - 1) // ROWS_PER_PAGE)
        page_state = {"index": 0, "total": total_pages}
        view_mode = {"mode": "table"}
        zoom_state = {"level": 0}

        # ── Build model ────────────────────────────────────────────────────
        model = CsvTableModel(csv_state["headers"], csv_state["all_rows"])
        self._table_model = model

        # ── Control bar ────────────────────────────────────────────────────
        ctrl = QWidget()
        ctrl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        ctrl_layout = QHBoxLayout(ctrl)
        ctrl_layout.setContentsMargins(0, 2, 0, 2)
        ctrl_layout.setSpacing(5)

        # View toggle
        table_btn = QPushButton("⊞ Table")
        raw_btn   = QPushButton("☰ Raw")
        for b in (table_btn, raw_btn):
            b.setCheckable(True)
            b.setFixedHeight(26)
        table_btn.setChecked(True)
        ctrl_layout.addWidget(table_btn)
        ctrl_layout.addWidget(raw_btn)

        # Separator selector
        ctrl_layout.addWidget(QLabel("Sep:"))
        sep_box = QComboBox()
        sep_box.setView(QListView())
        sep_box.addItems(["auto", ",", ";", "tab", "|"])
        _sep_display = {",": ",", ";": ";", "\t": "tab", "|": "|"}
        sep_box.setCurrentText(_sep_display.get(csv_state["separator"], "auto"))
        sep_box.setFixedWidth(60)
        ctrl_layout.addWidget(sep_box)

        # Header checkbox
        header_chk = QCheckBox("Header")
        header_chk.setChecked(csv_state["has_header"])
        ctrl_layout.addWidget(header_chk)

        # Zoom (raw mode only — hidden by default)
        zoom_out_btn = QPushButton("➖")
        zoom_in_btn  = QPushButton("➕")
        zoom_out_btn.setFixedSize(26, 26)
        zoom_in_btn.setFixedSize(26, 26)
        zoom_out_btn.setVisible(False)
        zoom_in_btn.setVisible(False)
        ctrl_layout.addWidget(zoom_out_btn)
        ctrl_layout.addWidget(zoom_in_btn)

        # Edit
        edit_chk = QCheckBox("Edit")
        ctrl_layout.addWidget(edit_chk)

        # Search
        search_field = ExpandingLineEdit()
        search_field.setPlaceholderText("Search...")
        search_field.setMinimumWidth(120)
        ctrl_layout.addWidget(search_field)

        find_prev_btn = QPushButton("▲")
        find_next_btn = QPushButton("▼")
        find_prev_btn.setFixedSize(26, 26)
        find_next_btn.setFixedSize(26, 26)
        find_prev_btn.setEnabled(False)
        find_next_btn.setEnabled(False)
        ctrl_layout.addWidget(find_prev_btn)
        ctrl_layout.addWidget(find_next_btn)

        count_label = QLabel("0 matches")
        ctrl_layout.addWidget(count_label)
        ctrl_layout.addStretch()

        # Page navigation
        page_prev_btn = QPushButton("◀")
        page_edit     = QLineEdit("1")
        page_info     = QLabel(f"/{page_state['total']} pages")
        page_next_btn = QPushButton("▶")
        page_prev_btn.setFixedSize(26, 26)
        page_next_btn.setFixedSize(26, 26)
        page_edit.setFixedWidth(36)
        page_prev_btn.setEnabled(False)
        page_next_btn.setEnabled(page_state["total"] > 1)
        ctrl_layout.addWidget(page_prev_btn)
        ctrl_layout.addWidget(page_edit)
        ctrl_layout.addWidget(page_info)
        ctrl_layout.addWidget(page_next_btn)

        layout.addWidget(ctrl)

        # ── Table view ─────────────────────────────────────────────────────
        table_view = QTableView()
        table_view.setModel(model)
        table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        table_view.horizontalHeader().setStretchLastSection(True)
        table_view.verticalHeader().setDefaultSectionSize(22)
        table_view.setAlternatingRowColors(True)
        table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        table_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table_view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(table_view)

        # ── Raw text view ──────────────────────────────────────────────────
        raw_widget = CustomTextEdit(self.parent)
        self.text_widget = raw_widget
        line_color = self.parent.qss_QPainter.get("painter_lines")
        raw_widget.setStyleSheet(
            f"border-top: 2px solid {line_color}; border-bottom: none; "
            f"border-left: none; border-right: none;"
        )
        raw_widget.setReadOnly(True)
        raw_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        raw_widget.setVisible(False)
        layout.addWidget(raw_widget)

        if self.parent is not None and hasattr(self.parent, "text_loaders"):
            self.parent.text_loaders.append(raw_widget)

        # ── Status bar ─────────────────────────────────────────────────────
        status_label = QLabel()
        status_label.setStyleSheet("font-style: italic;")
        status_label.setEnabled(False)
        layout.addWidget(status_label)

        # ── Raw page helpers ───────────────────────────────────────────────
        raw_lines = raw_text.splitlines(keepends=True)
        raw_header_line = raw_lines[0] if csv_state["has_header"] and raw_lines else ""
        raw_body_lines  = raw_lines[1:] if csv_state["has_header"] and raw_lines else raw_lines

        def get_raw_page(idx):
            start = idx * ROWS_PER_PAGE
            chunk = raw_body_lines[start: start + ROWS_PER_PAGE]
            return raw_header_line + "".join(chunk)

        raw_widget.setPlainText(get_raw_page(0))

        # ── Status update ──────────────────────────────────────────────────
        def update_status():
            try:
                sz = os.path.getsize(path)
                sz_str = (f"{sz} B" if sz < 1024 else
                          f"{sz/1024:.1f} KB" if sz < 1024**2 else
                          f"{sz/1024**2:.1f} MB")
                try:
                    perms = stat.filemode(os.stat(path).st_mode)
                except Exception:
                    perms = "N/A"
                sep_repr = repr(csv_state["separator"])
                status_label.setText(
                    f"File size: {sz_str} | Rows: {len(csv_state['all_rows'])} | "
                    f"Columns: {len(csv_state['headers'])} | "
                    f"Separator: {sep_repr} | Permissions: {perms}"
                )
            except Exception:
                pass

        update_status()

        # ── Page UI refresh ────────────────────────────────────────────────
        def refresh_page_ui():
            idx = page_state["index"]
            tot = page_state["total"]
            page_edit.setText(str(idx + 1))
            page_info.setText(f"/{tot} pages")
            page_prev_btn.setEnabled(idx > 0)
            page_next_btn.setEnabled(idx < tot - 1)

        # ── Load a page ────────────────────────────────────────────────────
        def load_page(idx):
            page_state["index"] = idx
            model.set_page(idx * ROWS_PER_PAGE)
            raw_widget.setPlainText(get_raw_page(idx))
            refresh_page_ui()
            # Re-apply active search
            txt = search_field.text().strip()
            if txt:
                model.set_search(txt)
                if view_mode["mode"] == "table":
                    _refresh_table_search(txt)
                else:
                    _refresh_raw_search(txt)

        # ── View toggle ────────────────────────────────────────────────────
        def switch_to_table():
            view_mode["mode"] = "table"
            table_btn.setChecked(True)
            raw_btn.setChecked(False)
            table_view.setVisible(True)
            raw_widget.setVisible(False)
            zoom_out_btn.setVisible(False)
            zoom_in_btn.setVisible(False)
            _refresh_table_search(search_field.text().strip())

        def switch_to_raw():
            view_mode["mode"] = "raw"
            raw_btn.setChecked(True)
            table_btn.setChecked(False)
            raw_widget.setVisible(True)
            table_view.setVisible(False)
            zoom_out_btn.setVisible(True)
            zoom_in_btn.setVisible(True)
            _refresh_raw_search(search_field.text().strip())

        table_btn.clicked.connect(switch_to_table)
        raw_btn.clicked.connect(switch_to_raw)

        # ── Search: table ──────────────────────────────────────────────────
        table_nav = {"matches": [], "idx": -1}

        def _refresh_table_search(txt):
            model.set_search(txt)
            if not txt:
                count_label.setText("0 matches")
                find_prev_btn.setEnabled(False)
                find_next_btn.setEnabled(False)
                table_nav["matches"] = []
                table_nav["idx"] = -1
                return
            matches = model.page_matches(txt)
            table_nav["matches"] = matches
            table_nav["idx"] = -1
            total = model.total_matches(txt)
            count_label.setText(f"{total} matches")
            find_prev_btn.setEnabled(bool(matches))
            find_next_btn.setEnabled(bool(matches))

        # ── Search: raw ────────────────────────────────────────────────────
        fmt_hl = QTextCharFormat()
        fmt_hl.setBackground(QColor("yellow"))
        raw_nav = {"positions": [], "idx": -1}

        def _refresh_raw_search(txt):
            if not txt:
                raw_widget.setExtraSelections([])
                raw_nav["positions"] = []
                raw_nav["idx"] = -1
                count_label.setText("0 matches")
                find_prev_btn.setEnabled(False)
                find_next_btn.setEnabled(False)
                return
            full = raw_widget.toPlainText()
            needle = txt.lower()
            hay = full.lower()
            sels = []
            positions = []
            start = 0
            while len(positions) < 10_000:
                idx = hay.find(needle, start)
                if idx == -1:
                    break
                cur = QTextCursor(raw_widget.document())
                cur.setPosition(idx)
                cur.setPosition(idx + len(txt), QTextCursor.MoveMode.KeepAnchor)
                sel = QTextEdit.ExtraSelection()
                sel.cursor = cur
                sel.format = fmt_hl
                sels.append(sel)
                positions.append((idx, len(txt)))
                start = idx + len(txt)
            raw_widget.setExtraSelections(sels)
            raw_nav["positions"] = positions
            raw_nav["idx"] = -1
            count_label.setText(f"{len(positions)} matches")
            find_prev_btn.setEnabled(bool(positions))
            find_next_btn.setEnabled(bool(positions))

        # ── Search navigation ──────────────────────────────────────────────
        def _nav_table(direction):
            matches = table_nav["matches"]
            if not matches:
                return
            n = len(matches)
            table_nav["idx"] = (table_nav["idx"] + (1 if direction == "next" else -1)) % n
            r, c = matches[table_nav["idx"]]
            idx = model.index(r, c)
            table_view.scrollTo(idx)
            table_view.setCurrentIndex(idx)

        def _nav_raw(direction):
            positions = raw_nav["positions"]
            if not positions:
                return
            n = len(positions)
            raw_nav["idx"] = (raw_nav["idx"] + (1 if direction == "next" else -1)) % n
            start, length = positions[raw_nav["idx"]]
            cur = QTextCursor(raw_widget.document())
            cur.setPosition(start)
            cur.setPosition(start + length, QTextCursor.MoveMode.KeepAnchor)
            raw_widget.setTextCursor(cur)
            raw_widget.ensureCursorVisible()

        def on_find_next():
            if view_mode["mode"] == "table":
                _nav_table("next")
            else:
                _nav_raw("next")

        def on_find_prev():
            if view_mode["mode"] == "table":
                _nav_table("prev")
            else:
                _nav_raw("prev")

        find_next_btn.clicked.connect(on_find_next)
        find_prev_btn.clicked.connect(on_find_prev)

        # ── Search debounce ────────────────────────────────────────────────
        self.search_debounce_timer = QTimer()
        self.search_debounce_timer.setSingleShot(True)
        self.search_debounce_timer.setInterval(300)

        def on_debounce():
            txt = search_field.text().strip()
            if view_mode["mode"] == "table":
                _refresh_table_search(txt)
            else:
                _refresh_raw_search(txt)

        self.search_debounce_timer.timeout.connect(on_debounce)
        search_field.textChanged.connect(lambda _=None: self.search_debounce_timer.start())

        # ── Zoom (raw only) ────────────────────────────────────────────────
        MIN_ZOOM, MAX_ZOOM = -10, 40

        def _zoom_in():
            if zoom_state["level"] < MAX_ZOOM:
                raw_widget.zoomIn(1)
                zoom_state["level"] += 1
            zoom_in_btn.setEnabled(zoom_state["level"] < MAX_ZOOM)
            zoom_out_btn.setEnabled(zoom_state["level"] > MIN_ZOOM)

        def _zoom_out():
            if zoom_state["level"] > MIN_ZOOM:
                raw_widget.zoomOut(1)
                zoom_state["level"] -= 1
            zoom_in_btn.setEnabled(zoom_state["level"] < MAX_ZOOM)
            zoom_out_btn.setEnabled(zoom_state["level"] > MIN_ZOOM)

        zoom_in_btn.clicked.connect(_zoom_in)
        zoom_out_btn.clicked.connect(_zoom_out)

        # ── Edit mode ──────────────────────────────────────────────────────
        def on_edit_toggled(state):
            checked = bool(state)
            model.set_editable(checked)
            if checked:
                table_view.setEditTriggers(
                    QAbstractItemView.EditTrigger.DoubleClicked |
                    QAbstractItemView.EditTrigger.EditKeyPressed
                )
            else:
                table_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
                _save_csv()

        edit_chk.stateChanged.connect(on_edit_toggled)

        # ── Save CSV ───────────────────────────────────────────────────────
        def _save_csv():
            try:
                buf = io.StringIO()
                writer = csv.writer(buf, delimiter=csv_state["separator"])
                if csv_state["has_header"]:
                    writer.writerow(csv_state["headers"])
                for row in csv_state["all_rows"]:
                    writer.writerow(row)
                text = buf.getvalue()
                threading.Thread(
                    target=self._write_chunks_to_disk,
                    args=([text], path),
                    daemon=True,
                ).start()
            except Exception:
                pass

        # ── Reload on separator / header change ────────────────────────────
        def _reload(new_sep=None, new_has_header=None):
            nonlocal raw_header_line, raw_body_lines
            actual_sep        = new_sep        if new_sep        is not None else csv_state["separator"]
            actual_has_header = new_has_header if new_has_header is not None else csv_state["has_header"]
            try:
                parsed = list(csv.reader(io.StringIO(raw_text), delimiter=actual_sep))
                if parsed and actual_has_header:
                    new_headers   = parsed[0]
                    new_data_rows = parsed[1:]
                elif parsed:
                    new_headers   = [f"Col {i + 1}" for i in range(len(parsed[0]))]
                    new_data_rows = parsed
                else:
                    new_headers, new_data_rows = [], []

                nc = len(new_headers)
                for r in new_data_rows:
                    if len(r) < nc:
                        r.extend([""] * (nc - len(r)))

                csv_state["headers"]    = new_headers
                csv_state["all_rows"]   = new_data_rows
                csv_state["separator"]  = actual_sep
                csv_state["has_header"] = actual_has_header

                model.reset_data(new_headers, new_data_rows)

                # Rebuild raw page split
                raw_header_line = raw_lines[0] if actual_has_header and raw_lines else ""
                raw_body_lines  = raw_lines[1:] if actual_has_header and raw_lines else raw_lines

                new_total = max(1, (len(new_data_rows) + ROWS_PER_PAGE - 1) // ROWS_PER_PAGE)
                page_state["index"] = 0
                page_state["total"] = new_total
                raw_widget.setPlainText(get_raw_page(0))
                refresh_page_ui()
                update_status()
            except Exception:
                pass

        def on_sep_changed(text):
            sep_map = {"auto": ",", ",": ",", ";": ";", "tab": "\t", "|": "|"}
            _reload(new_sep=sep_map.get(text, ","))

        def on_header_toggled(state):
            _reload(new_has_header=bool(state))

        sep_box.currentTextChanged.connect(on_sep_changed)
        header_chk.stateChanged.connect(on_header_toggled)

        # ── Page navigation ────────────────────────────────────────────────
        def on_page_prev():
            if page_state["index"] > 0:
                load_page(page_state["index"] - 1)

        def on_page_next():
            if page_state["index"] < page_state["total"] - 1:
                load_page(page_state["index"] + 1)

        def on_page_edit_enter():
            try:
                n = max(1, min(int(page_edit.text()), page_state["total"]))
                load_page(n - 1)
            except ValueError:
                page_edit.setText(str(page_state["index"] + 1))

        page_prev_btn.clicked.connect(on_page_prev)
        page_next_btn.clicked.connect(on_page_next)
        page_edit.returnPressed.connect(on_page_edit_enter)

        refresh_page_ui()

    # ── cleanup ────────────────────────────────────────────────────────────

    def cleanup(self, timeout_ms=100):
        try:
            if self.text_widget is not None and self.parent is not None:
                try:
                    self.parent.text_loaders.remove(self.text_widget)
                except (ValueError, Exception):
                    pass

            for attr in ("search_debounce_timer",):
                timer = getattr(self, attr, None)
                if timer is not None:
                    try:
                        timer.stop()
                    except Exception:
                        pass

            if getattr(self, "worker", None) is not None:
                try:
                    self.worker.finished.disconnect()
                except Exception:
                    pass

            if getattr(self, "thread", None) is not None:
                try:
                    self.thread.quit()
                    self.thread.wait(timeout_ms)
                except Exception:
                    pass
                self.thread = None

            self._table_model = None

        except Exception:
            pass

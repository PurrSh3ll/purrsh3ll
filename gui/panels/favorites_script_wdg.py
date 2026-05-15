from functools import partial
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHeaderView, QSizePolicy, QTextEdit, QHBoxLayout
)
from PyQt6.QtCore import Qt, QTimer, QSize, QObject, pyqtSignal, QThread
import csv, os

from gui.widgets.wrap_delegate import WrapAnywhereDelegate

class FavoritesLoader(QObject):
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, fav_path: str):
        super().__init__()
        self.fav_path = fav_path

    def run(self):
        try:
            if not self.fav_path or not os.path.exists(self.fav_path):
                self.finished.emit([])
                return

            with open(self.fav_path, "r", encoding="utf-8", newline="") as f:
                reader = csv.reader(f)
                rows = list(reader)

            records = []
            for row in rows:
                if not row:
                    continue
                row = [c.strip() for c in row]
                if len(row) >= 3:
                    name = row[0]
                    description = row[1]
                    command = ", ".join(row[2:])
                    records.append((name, command, description))
                elif len(row) == 2:
                    records.append((row[0], "", row[1]))
                else:
                    records.append((row[0], "", ""))

            self.finished.emit(records)

        except Exception as e:
            self.error.emit(str(e))

class FavScriptWdg(QWidget):
    HEADERS = ["Id", "Name", "Command", "Description", "Action"]
    EMPTY_TEXT = "[-] Execution history is empty. The program has not been launched."

    def __init__(self, fav_path, parent=None, main_script=None,
                 name_column_width: int = 180, desc_column_width: int = 300,
                 action_column_width: int = 120, id_column_width: int = 60,
                 min_command_width: int = 200, resize_debounce_ms: int = 300,
                 action_button_size: int = 28):
        super().__init__(parent)
        self.fav_path = fav_path
        self.main_script = main_script
        self.records = []
        self._name_col_w = name_column_width
        self._desc_col_w = desc_column_width
        self._action_col_w = action_column_width
        self._id_col_w = id_column_width
        self._min_command_w = min_command_width
        self._resize_debounce_ms = resize_debounce_ms
        self._btn_size = action_button_size
        self._build_ui()
        self.update_data_async()

    def update_data_async(self):
        empty_msg = (
            "[-] Your Favorites list is currently empty. "
            "To add a command, go to the History tab and select command"
        )

        if not self.fav_path:
            self.table.hide()
            self.empty_field.show()
            self.empty_field.setText(empty_msg)
            self.records = []
            return

        self.thread = QThread(self)
        self.worker = FavoritesLoader(self.fav_path)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._on_fav_loaded)
        self.worker.error.connect(self._on_fav_error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def _on_fav_loaded(self, records: list):
        empty_msg = (
            "[-] Your Favorites list is currently empty. "
            "To add a command, go to the History tab and select command"
        )
        if not records:
            self.table.hide()
            self.empty_field.show()
            self.empty_field.setText(empty_msg)
            self.records = []
            return
        self.records = [(str(n), str(c), str(d)) for n, c, d in records]
        self.empty_field.hide()
        self.table.show()
        self._populate_table()

    def _on_fav_error(self, msg: str):
        pass

    def _parse_rows_into_records(self, rows):
        records = []
        for row in rows:
            if not row:
                continue
            row = [cell.strip() if isinstance(cell, str) else "" for cell in row]
            if len(row) >= 3:
                name = row[0]
                description = row[1]
                command = ", ".join(row[2:]).strip()
                records.append((name, command, description))
            elif len(row) == 2:
                name = row[0]
                description = row[1]
                records.append((name, "", description))
            else:
                name = row[0]
                records.append((name, "", ""))
        return records

    def _load_records_from_fav(self):
        if not self.fav_path:
            return []
        if not os.path.exists(self.fav_path):
            return []
        try:
            with open(self.fav_path, "r", encoding="utf-8", newline="") as f:
                reader = csv.reader(f)
                rows = list(reader)
        except Exception:
            return []
        return self._parse_rows_into_records(rows)

    def _build_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)

        self.table = QTableWidget(self)
        self.table.setColumnCount(len(self.HEADERS))
        self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.table.verticalHeader().setVisible(False)

        header = self.table.horizontalHeader()
        header.setSectionsClickable(False)

        for col in range(self.table.columnCount()):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Fixed)

        self.table.setColumnWidth(0, self._id_col_w)
        self.table.setColumnWidth(1, self._name_col_w)
        self.table.setColumnWidth(3, self._desc_col_w)
        self.table.setColumnWidth(4, self._action_col_w)
        self.table.setWordWrap(True)

        delegate = WrapAnywhereDelegate(self.table)
        self.table.setItemDelegateForColumn(1, delegate)
        self.table.setItemDelegateForColumn(2, delegate)
        self.table.setItemDelegateForColumn(3, delegate)

        header.setMinimumSectionSize(30)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        self.empty_field = QTextEdit(self.EMPTY_TEXT)
        self.empty_field.setReadOnly(True)
        self.empty_field.hide()

        self.layout.addWidget(self.table)
        self.layout.addWidget(self.empty_field)

        self._resize_timer = QTimer(self)
        self._resize_timer.setSingleShot(True)
        self._resize_timer.timeout.connect(self._on_resize_finished)
        header.sectionResized.connect(self._on_section_resized)

    def _clear_table_widgets(self):
        row_count = self.table.rowCount()
        col_count = self.table.columnCount()
        for r in range(row_count):
            for c in range(col_count):
                w = self.table.cellWidget(r, c)
                if w:
                    self.table.removeCellWidget(r, c)
                    w.deleteLater()

    def _populate_table(self):
        self._clear_table_widgets()
        self.table.clearContents()
        self.table.setRowCount(len(self.records))

        for row_idx, (name, command, description) in enumerate(self.records):
            item_id = QTableWidgetItem(str(row_idx + 1))
            item_id.setFlags(item_id.flags() ^ Qt.ItemFlag.ItemIsEditable)
            item_id.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row_idx, 0, item_id)

            name_item = QTableWidgetItem(name)
            name_item.setFlags(name_item.flags() ^ Qt.ItemFlag.ItemIsEditable)
            name_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            name_item.setData(Qt.ItemDataRole.DisplayRole, name)
            self.table.setItem(row_idx, 1, name_item)

            cmd_item = QTableWidgetItem(command)
            cmd_item.setFlags(cmd_item.flags() ^ Qt.ItemFlag.ItemIsEditable)
            cmd_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            cmd_item.setData(Qt.ItemDataRole.DisplayRole, command)
            self.table.setItem(row_idx, 2, cmd_item)

            desc_item = QTableWidgetItem(description)
            desc_item.setFlags(desc_item.flags() ^ Qt.ItemFlag.ItemIsEditable)
            desc_item.setData(Qt.ItemDataRole.DisplayRole, description)
            desc_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(row_idx, 3, desc_item)

            action_widget = QWidget()
            hbox = QHBoxLayout(action_widget)
            hbox.setContentsMargins(4, 0, 4, 0)
            spacing = 6
            hbox.setSpacing(spacing)

            btn_run = QPushButton("⏎")
            btn_copy = QPushButton("⧉")
            btn_delete = QPushButton("🗑")

            btn_run.setFixedSize(self._btn_size, self._btn_size)
            btn_copy.setFixedSize(self._btn_size, self._btn_size)
            btn_delete.setFixedSize(self._btn_size, self._btn_size)

            for b in (btn_run, btn_copy, btn_delete):
                b.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

            btn_run.clicked.connect(partial(self._btn_run_clicked, row_idx))
            btn_copy.clicked.connect(partial(self._btn_copy_clicked, row_idx))
            btn_delete.clicked.connect(partial(self._btn_delete_clicked, row_idx))

            hbox.addWidget(btn_run)
            hbox.addWidget(btn_copy)
            hbox.addWidget(btn_delete)
            hbox.addStretch()

            self.table.setCellWidget(row_idx, 4, action_widget)

        self.table.resizeColumnToContents(0)
        id_w = max(self.table.columnWidth(0), self._id_col_w)
        self.table.setColumnWidth(0, id_w)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)

        action_w = max(self._action_col_w, self._btn_size * 3 + (spacing * 2) + 8 + 4)
        self.table.setColumnWidth(4, action_w)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)

        self.table.setColumnWidth(1, self._name_col_w)
        self.table.setColumnWidth(3, self._desc_col_w)
        self._adjust_command_column_width()
        self.table.resizeRowsToContents()

    def _adjust_command_column_width(self):
        total_width = self.table.viewport().width()
        id_w = self.table.columnWidth(0)
        name_w = self.table.columnWidth(1)
        desc_w = self.table.columnWidth(3)
        action_w = self.table.columnWidth(4)
        vs = self.table.verticalScrollBar()
        scrollbar_w = vs.width() if vs.isVisible() else 0
        other = id_w + name_w + desc_w + action_w + scrollbar_w
        desired = max(self._min_command_w, total_width - other - 2)
        if desired < 0:
            desired = self._min_command_w
        self.table.setColumnWidth(2, desired)
        self.table.resizeRowsToContents()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._resize_timer.start(self._resize_debounce_ms)

    def _on_section_resized(self, logicalIndex: int, oldSize: int, newSize: int):
        self._resize_timer.start(self._resize_debounce_ms)

    def _on_resize_finished(self):
        self._adjust_command_column_width()

    def update_data(self):
        empty_msg = (
            "[-] Your Favorites list is currently empty. "
            "To add a command, go to the History tab and select command"
        )
        if self.fav_path:
            records = self._load_records_from_fav()
            if not records:
                self.table.hide()
                self.empty_field.show()
                self.empty_field.setText(empty_msg)
                self.records = []
                return
            self.records = [(str(n), str(c), str(d)) for n, c, d in records]
            self.empty_field.hide()
            self.table.show()
            self._populate_table()
            return
        self.table.hide()
        self.empty_field.show()
        self.empty_field.setText(empty_msg)
        self.records = []

    def update_records(self, records: list):
        if not records:
            self.update_data()
            return
        self.empty_field.hide()
        self.table.show()
        self.records = [(str(n), str(c), str(d)) for n, c, d in records]
        self._populate_table()

    def _btn_run_clicked(self, row_idx):
        if row_idx < 0 or row_idx >= len(self.records):
            return
        name, command, description = self.records[row_idx]
        self.main_script._execute_command(command + "\n")

    def _btn_copy_clicked(self, row_idx):
        if row_idx < 0 or row_idx >= len(self.records):
            return
        name, command, description = self.records[row_idx]
        self.main_script._execute_command(command)

    def _btn_delete_clicked(self, row_idx: int):
        if row_idx < 0 or row_idx >= len(self.records):
            return
        ok = self._delete_record_from_file(row_idx)
        if not ok:
            return
        del self.records[row_idx]
        if not self.records:
            self.update_data_async()
        else:
            self._populate_table()

    def _delete_record_from_file(self, row_idx: int):
        if not self.fav_path or not os.path.exists(self.fav_path):
            return False
        try:
            with open(self.fav_path, "r", encoding="utf-8", newline="") as f:
                rows = list(csv.reader(f))
            if row_idx < 0 or row_idx >= len(rows):
                return False
            del rows[row_idx]
            with open(self.fav_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
                writer.writerows(rows)
            return True
        except Exception as e:
            return False

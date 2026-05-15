from functools import partial
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHeaderView, QSizePolicy, QTextEdit, QDialog,
    QLabel, QLineEdit, QDialogButtonBox, QHBoxLayout
)
from PyQt6.QtCore import Qt, QTimer, QSize, QObject, QThread, pyqtSignal
import sys, csv, os

from gui.widgets.wrap_delegate import WrapAnywhereDelegate

class FavoriteDialog(QDialog):
    def __init__(self, command_text: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Save favorite")
        self.setModal(True)
        self.resize(600, 300)

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Command:"))
        self.command_edit = QTextEdit()
        self.command_edit.setPlainText(command_text)
        layout.addWidget(self.command_edit)

        layout.addWidget(QLabel("Name:"))
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Enter optional name...")
        layout.addWidget(self.name_edit)

        layout.addWidget(QLabel("Description:"))
        self.desc_edit = QTextEdit()
        self.desc_edit.setPlaceholderText("Write optional description...")
        layout.addWidget(self.desc_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_values(self):
        return (self.name_edit.text(), self.desc_edit.toPlainText(), self.command_edit.toPlainText())

class HistoryLoader(QObject):
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, hist_path: str):
        super().__init__()
        self.hist_path = hist_path

    def run(self):
        try:
            if not self.hist_path or not os.path.exists(self.hist_path):
                self.finished.emit([])
                return

            if os.path.getsize(self.hist_path) == 0:
                self.finished.emit([])
                return

            with open(self.hist_path, "r", encoding="utf-8") as f:
                content = f.read()

            records = []
            reader = csv.reader(content.splitlines(), skipinitialspace=True)
            for row in reader:
                if not row:
                    continue
                if len(row) >= 2:
                    command = row[0].strip()
                    date = ", ".join(p.strip() for p in row[1:])
                    if command.startswith('"') and command.endswith('"'):
                        command = command[1:-1]
                    records.append((command, date))
                else:
                    records.append((row[0].strip(), ""))

            self.finished.emit(records)

        except Exception as e:
            self.error.emit(str(e))

class HistoryScriptWdg(QWidget):
    HEADERS = ["Id", "Command", "Date", "Favorites"]
    EMPTY_TEXT = "[-] Execution history is empty. The program has not been launched."

    def __init__(self, hist_path=None, fav_path=None, parent=None, fav_obj=None,
                 date_column_width: int = 180, fav_column_width: int = 80, id_column_width: int = 60,
                 min_command_width: int = 200, resize_debounce_ms: int = 300,
                 fav_button_size: int = 28):
        super().__init__(parent)
        self.content = ""
        self.hist_path = hist_path
        self.fav_path = fav_path
        self.fav_obj = fav_obj
        self.records = []
        self._date_col_w = date_column_width
        self._fav_col_w = fav_column_width
        self._id_col_w = id_column_width
        self._min_command_w = min_command_width
        self._resize_debounce_ms = resize_debounce_ms
        self._fav_btn_size = fav_button_size

        self._build_ui()
        self.update_data_async()

    def update_data_async(self):
        self.thread = QThread(self)
        self.worker = HistoryLoader(self.hist_path)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._on_data_loaded)
        self.worker.error.connect(self._on_data_error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def _on_data_loaded(self, records: list):
        if not records:
            self.table.hide()
            self.empty_field.show()
            self.empty_field.setText(self.EMPTY_TEXT)
            return
        self.empty_field.hide()
        self.table.show()
        self.records = records
        self._populate_table()

    def _on_data_error(self, msg: str):
        pass

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
        self.table.setColumnWidth(2, self._date_col_w)
        self.table.setColumnWidth(3, self._fav_col_w)
        self.table.setWordWrap(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        delegate = WrapAnywhereDelegate(self.table)
        self.table.setItemDelegateForColumn(1, delegate)

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

        for row_idx, (command, date) in enumerate(self.records):
            item_id = QTableWidgetItem(str(row_idx + 1))
            item_id.setFlags(item_id.flags() ^ Qt.ItemFlag.ItemIsEditable)
            item_id.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row_idx, 0, item_id)

            cmd_item = QTableWidgetItem(command)
            cmd_item.setFlags(cmd_item.flags() ^ Qt.ItemFlag.ItemIsEditable)
            cmd_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            cmd_item.setData(Qt.ItemDataRole.DisplayRole, command)
            self.table.setItem(row_idx, 1, cmd_item)

            date_item = QTableWidgetItem(date)
            date_item.setFlags(date_item.flags() ^ Qt.ItemFlag.ItemIsEditable)
            date_item.setData(Qt.ItemDataRole.DisplayRole, date)
            date_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(row_idx, 2, date_item)

            btn = QPushButton("+")
            btn.setFixedSize(self._fav_btn_size, self._fav_btn_size)
            btn.clicked.connect(partial(self._on_favorite_clicked, row_idx))

            wrapper = QWidget()
            h = QHBoxLayout(wrapper)
            h.setContentsMargins(4, 0, 4, 0)
            h.addStretch()
            h.addWidget(btn)
            h.addStretch()
            self.table.setCellWidget(row_idx, 3, wrapper)

        self.table.setColumnWidth(0, self._id_col_w)
        self.table.setColumnWidth(3, max(self._fav_col_w, self._fav_btn_size + 12))
        self._adjust_command_column_width()
        self.table.resizeRowsToContents()

    def _adjust_command_column_width(self):
        total_width = self.table.viewport().width()
        id_w = self.table.columnWidth(0)
        date_w = self.table.columnWidth(2)
        fav_w = self.table.columnWidth(3)
        vs = self.table.verticalScrollBar()
        scrollbar_w = vs.width() if vs.isVisible() else 0
        other = id_w + date_w + fav_w + scrollbar_w
        desired = max(self._min_command_w, total_width - other - 2)
        if desired < 0:
            desired = self._min_command_w
        self.table.setColumnWidth(1, desired)
        self.table.resizeRowsToContents()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._resize_timer.start(self._resize_debounce_ms)

    def _on_section_resized(self, logicalIndex: int, oldSize: int, newSize: int):
        self._resize_timer.start(self._resize_debounce_ms)

    def _on_resize_finished(self):
        self._adjust_command_column_width()

    def _on_favorite_clicked(self, row_idx: int):
        if row_idx < 0 or row_idx >= len(self.records):
            return
        command, date = self.records[row_idx]
        dlg = FavoriteDialog(command_text=command, parent=self)
        result = dlg.exec()
        if result == QDialog.DialogCode.Accepted:
            name, description, new_command = dlg.get_values()
            self.save_favorite(name=name, description=description, command=new_command, row_idx=row_idx)

    def save_favorite(self, name: str, description: str, command: str, row_idx: int | None = None):
        new_row = [name, description, command]
        os.makedirs(os.path.dirname(self.fav_path), exist_ok=True)
        with open(self.fav_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(new_row)
        self.fav_obj.update_data_async()


import os
import json

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QLineEdit,
    QPushButton, QSizePolicy, QStackedWidget, QScrollArea, QComboBox,
    QGridLayout, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QMovie

BUTTON_NAMES = ["create", "stagers", "listeners", "keyloggers", "harvesters", "agents"]

CREATE_ROWS = [
    ("CATEGORY", "combobox"),
    ("OS",       "combobox"),
    ("ARCH",     "combobox"),
    ("STAGE",    "combobox"),
    ("TYPE",     "combobox"),
    ("ENCODER",  "combobox"),
    ("ITER",     "combobox"),
    ("FORMAT",   "combobox"),
    ("LHOST",    "lineedit"),
    ("LPORT",    "lineedit"),
    ("OUTPUT",   "lineedit"),
]

WIDGET_MAX_WIDTH = 300
STAGERS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "appmodules", "Cyb3rCollector", "stagers"
)
LISTENERS_DIR = os.path.join(os.path.dirname(STAGERS_DIR), "listeners")

class Psc2_file(QWidget):
    def __init__(self):
        super().__init__()
        self._controller = None
        self._purr_path = None

    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        self._controller = parent
        self._purr_path = path
        self.qss_messagebox = parent.messagebox_stylesheet

        malware_options = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            malware_options = data.get("malware_options", {})
        except Exception:
            pass

        scroll = QScrollArea(parent=parent.widgets['execution_tabs'])
        scroll.setWidgetResizable(True)
        scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        container = QWidget(parent=scroll)
        root_layout = QVBoxLayout(container)
        root_layout.setContentsMargins(6, 6, 6, 6)
        root_layout.setSpacing(6)
        container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        scroll.setWidget(container)

        buttons_row = QHBoxLayout()
        buttons_row.setSpacing(6)

        self.buttons = []
        for name in BUTTON_NAMES:
            btn = QPushButton(name)
            btn.setFixedHeight(28)
            btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, b=btn: self._on_button_clicked(b))
            buttons_row.addWidget(btn)
            self.buttons.append(btn)

        root_layout.addLayout(buttons_row)

        self.central_stack = QStackedWidget()
        self.central_stack.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.welcome_field = QLabel()
        self.welcome_field.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gif_path = os.path.join(parent.icons_path, "psc2.gif") if parent and hasattr(parent, "icons_path") else ""
        self.movie = QMovie(gif_path)
        self.welcome_field.setMovie(self.movie)
        self.movie.start()
        self.central_stack.addWidget(self.welcome_field)

        self.create_widget = self._build_create_widget(malware_options)
        self.central_stack.addWidget(self.create_widget)

        self.stagers_table_widget = self._build_stagers_table_widget()
        self.central_stack.addWidget(self.stagers_table_widget)

        self.listeners_table_widget = self._build_listeners_table_widget()
        self.central_stack.addWidget(self.listeners_table_widget)

        self.content_field = QTextEdit()
        self.content_field.setReadOnly(True)
        self.content_field.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.content_field.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.central_stack.addWidget(self.content_field)

        self.central_stack.setCurrentWidget(self.welcome_field)
        root_layout.addWidget(self.central_stack)

        return scroll

    def _build_create_widget(self, malware_options: dict):
        widget = QWidget()
        outer = QHBoxLayout(widget)
        outer.setContentsMargins(12, 12, 12, 12)

        form_widget = QWidget()
        form_widget.setMaximumWidth(600)
        grid = QGridLayout(form_widget)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)
        grid.setColumnMinimumWidth(0, 80)
        grid.setColumnStretch(1, 1)

        self._category_combo = None
        self._format_combo = None
        self._output_edit = None
        self._form_widgets = {}
        self._stager_only_widgets = []

        for row, (label_text, widget_type) in enumerate(CREATE_ROWS):
            label = QLabel(label_text)
            label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            grid.addWidget(label, row, 0)

            value = malware_options.get(label_text)

            if widget_type == "combobox":
                right = QComboBox()
                if isinstance(value, list):
                    right.addItems([str(v) for v in value])
                elif value is not None:
                    right.addItem(str(value))
                if label_text == "CATEGORY":
                    self._category_combo = right
                elif label_text == "FORMAT":
                    self._format_combo = right
            else:
                right = QLineEdit()
                if value is not None:
                    right.setText(str(value))
                if label_text == "OUTPUT":
                    self._output_edit = right

            right.setMaximumWidth(WIDGET_MAX_WIDTH)
            right.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            grid.addWidget(right, row, 1)
            self._form_widgets[label_text] = right

            if label_text != "CATEGORY":
                self._stager_only_widgets.append((label, right))

        generate_row = len(CREATE_ROWS) + 1
        self._generate_btn = QPushButton("generate")
        self._generate_btn.setFixedHeight(28)
        self._generate_btn.setMaximumWidth(WIDGET_MAX_WIDTH)
        self._generate_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._generate_btn.clicked.connect(self._on_generate_clicked)
        grid.addWidget(self._generate_btn, generate_row, 1)
        self._stager_only_widgets.append((None, self._generate_btn))

        grid.setRowStretch(generate_row + 1, 1)

        outer.addWidget(form_widget)
        outer.addStretch()

        if self._category_combo:
            self._on_category_changed(self._category_combo.currentText())
            self._category_combo.currentTextChanged.connect(self._on_category_changed)

        return widget

    def _on_category_changed(self, text: str):
        visible = (text == "stager")
        for label, right in self._stager_only_widgets:
            if label is not None:
                label.setVisible(visible)
            right.setVisible(visible)

    def _on_generate_clicked(self):
        output = self._output_edit.text().strip() if self._output_edit else ""
        fmt = self._format_combo.currentText().strip() if self._format_combo else ""
        category = self._category_combo.currentText() if self._category_combo else ""

        if not output or not fmt:
            QMessageBox.warning(None, "Missing data", "OUTPUT and FORMAT must not be empty.")
            return

        os.makedirs(STAGERS_DIR, exist_ok=True)
        stager_file = os.path.join(STAGERS_DIR, f"{output}.{fmt}")

        if os.path.exists(stager_file):
            QMessageBox.warning(
                None, "File already exists",
                f"The file '{output}.{fmt}' already exists in stagers. No file was created."
            )
            return

        entry = {}
        for label_text, widget in self._form_widgets.items():
            if isinstance(widget, QComboBox):
                entry[label_text] = widget.currentText()
            elif isinstance(widget, QLineEdit):
                entry[label_text] = widget.text().strip()

        open(stager_file, "w").close()

        listener_entry = {
            "LHOST": entry.get("LHOST", ""),
            "LPORT": entry.get("LPORT", ""),
            "FORMAT": entry.get("FORMAT", ""),
        }

        try:
            with open(self._purr_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data.setdefault("stagers", {})[output] = entry
            data.setdefault("listeners", {})[output] = listener_entry
            with open(self._purr_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            QMessageBox.warning(None, "Save error", f"Could not update psc2.purr:\n{e}")
            return

        os.makedirs(LISTENERS_DIR, exist_ok=True)
        listener_file = os.path.join(LISTENERS_DIR, f"{output}.{fmt}.txt")
        with open(listener_file, "w", encoding="utf-8") as f:
            json.dump(entry, f, indent=2, ensure_ascii=False)

        QMessageBox.information(
            None, "Cyb3rCollector",
            f"Your {category} was saved in Cyb3rCollector."
        )

    def _build_stagers_table_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)

        self._stagers_table = QTableWidget()
        self._stagers_table.setColumnCount(5)
        self._stagers_table.setHorizontalHeaderLabels(["#", "NAME", "LHOST", "LPORT", "ACTION"])
        self._stagers_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._stagers_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._stagers_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._stagers_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._stagers_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._stagers_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._stagers_table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self._stagers_table.verticalHeader().setVisible(False)
        self._stagers_table.cellDoubleClicked.connect(self._on_stager_double_clicked)
        layout.addWidget(self._stagers_table)

        return widget

    def _refresh_stagers_table(self):
        stagers = {}
        try:
            with open(self._purr_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            stagers = data.get("stagers", {})
        except Exception:
            pass

        self._stagers_table.setRowCount(0)
        self._stagers_entries = {}

        for name, entry in stagers.items():
            fmt = entry.get("FORMAT", "")
            display_name = f"{name}.{fmt}" if fmt else name

            row = self._stagers_table.rowCount()
            self._stagers_table.insertRow(row)

            num_lbl = QLabel(str(row + 1))
            num_lbl.setContentsMargins(4, 0, 4, 0)
            num_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._stagers_table.setCellWidget(row, 0, num_lbl)

            for col, text in enumerate([display_name, str(entry.get("LHOST", "")), str(entry.get("LPORT", ""))]):
                lbl = QLabel(text)
                lbl.setContentsMargins(4, 0, 4, 0)
                if col == 0:
                    lbl.setProperty("stager_name", name)
                self._stagers_table.setCellWidget(row, col + 1, lbl)
            self._stagers_entries[name] = entry

            delete_btn = QPushButton("✖")
            delete_btn.setFixedWidth(36)
            delete_btn.clicked.connect(lambda checked, n=name, e=entry: self._on_delete_stager(n, e))
            self._stagers_table.setCellWidget(row, 4, delete_btn)

    def _on_stager_double_clicked(self, row: int, column: int):
        lbl = self._stagers_table.cellWidget(row, 1)
        if lbl is None:
            return
        name = lbl.property("stager_name")
        entry = self._stagers_entries.get(name, {})

        lines = "\n".join(f"{k}:  {v}" for k, v in entry.items())

        dialog = QMessageBox(self._controller.widgets['execution_tabs'])
        dialog.setStyleSheet(self.qss_messagebox)
        dialog.setWindowTitle(f"Stager — {lbl.text()}")
        dialog.setText(lines)
        dialog.setStandardButtons(QMessageBox.StandardButton.Ok)
        dialog.exec()

    def _on_delete_stager(self, name: str, entry: dict):
        fmt = entry.get("FORMAT", "")

        stager_file = os.path.join(STAGERS_DIR, f"{name}.{fmt}")
        if os.path.exists(stager_file):
            os.remove(stager_file)

        listener_file = os.path.join(LISTENERS_DIR, f"{name}.{fmt}.txt")
        if os.path.exists(listener_file):
            os.remove(listener_file)

        try:
            with open(self._purr_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data.get("stagers", {}).pop(name, None)
            with open(self._purr_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            QMessageBox.warning(None, "Delete error", f"Could not update psc2.purr:\n{e}")
            return

        self._refresh_stagers_table()

    def _build_listeners_table_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)

        self._listeners_table = QTableWidget()
        self._listeners_table.setColumnCount(5)
        self._listeners_table.setHorizontalHeaderLabels(["#", "NAME", "LHOST", "LPORT", "ACTION"])
        self._listeners_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._listeners_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._listeners_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._listeners_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._listeners_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._listeners_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._listeners_table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self._listeners_table.verticalHeader().setVisible(False)
        layout.addWidget(self._listeners_table)

        return widget

    def _refresh_listeners_table(self):
        listeners = {}
        try:
            with open(self._purr_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            listeners = data.get("listeners", {})
        except Exception:
            pass

        self._listeners_table.setRowCount(0)
        for name, entry in listeners.items():
            fmt = entry.get("FORMAT", "")
            display_name = f"{name}.{fmt}" if fmt else name

            row = self._listeners_table.rowCount()
            self._listeners_table.insertRow(row)

            num_lbl = QLabel(str(row + 1))
            num_lbl.setContentsMargins(4, 0, 4, 0)
            num_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            num_lbl.setProperty("confirmed", None)
            self._listeners_table.setCellWidget(row, 0, num_lbl)

            for col, text in enumerate([display_name, str(entry.get("LHOST", "")), str(entry.get("LPORT", ""))]):
                lbl = QLabel(text)
                lbl.setContentsMargins(4, 0, 4, 0)
                lbl.setProperty("confirmed", None)
                self._listeners_table.setCellWidget(row, col + 1, lbl)

            play_btn = QPushButton("▶")
            play_btn.setFixedWidth(36)
            play_btn.setProperty("confirmed", None)
            play_btn.clicked.connect(lambda checked, n=display_name, b=play_btn, r=row: self._on_listener_action(n, b, r))
            self._listeners_table.setCellWidget(row, 4, play_btn)

    def _on_listener_action(self, name: str, button: QPushButton, row: int):
        if not button.property("confirmed"):
            button.setText("✖")
            button.setProperty("confirmed", True)
            self._set_listener_row_confirmed(row, True)
            msg = QMessageBox(self._controller.widgets['execution_tabs'])
            msg.setStyleSheet(self.qss_messagebox)
            msg.setWindowTitle("Listener")
            msg.setText(f"Listener {name} is running.")
            msg.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg.exec()
        else:
            button.setText("▶")
            button.setProperty("confirmed", None)
            self._set_listener_row_confirmed(row, False)

    def _set_listener_row_confirmed(self, row: int, confirmed: bool):
        value = True if confirmed else None
        for col in range(self._listeners_table.columnCount()):
            widget = self._listeners_table.cellWidget(row, col)
            if widget:
                widget.setProperty("confirmed", value)
                widget.style().unpolish(widget)
                widget.style().polish(widget)

    def _on_button_clicked(self, button: QPushButton):
        currently_checked = button.isChecked()

        for b in self.buttons:
            if b is not button:
                b.setChecked(False)

        if currently_checked:
            if button.text() == "create":
                self.central_stack.setCurrentWidget(self.create_widget)
            elif button.text() == "stagers":
                self._refresh_stagers_table()
                self.central_stack.setCurrentWidget(self.stagers_table_widget)
            elif button.text() == "listeners":
                self._refresh_listeners_table()
                self.central_stack.setCurrentWidget(self.listeners_table_widget)
            else:
                self.content_field.setPlainText(button.text())
                self.central_stack.setCurrentWidget(self.content_field)
        else:
            self.central_stack.setCurrentWidget(self.welcome_field)

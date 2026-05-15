from PyQt6.QtWidgets import (QVBoxLayout, QApplication,
    QDialog, QLabel, QLineEdit, QPushButton, QMessageBox, QComboBox, QWidget,
                             QHBoxLayout, QInputDialog, QListView,
                             QTableWidgetItem, QTableWidget, QHeaderView, QAbstractItemView)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction
from core.controller import controller_instance
import os, json, subprocess, re

class CustomDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Dynamic Variables Options")
        self.resize(800, 650)
        self.c = controller_instance
        self.base_path = self.c.base_path

        layout = QVBoxLayout(self)

        self.table = QTableWidget()
        self.table.setAlternatingRowColors(True)
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Name", "Type", "Expression", "Description", "Action"
        ])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        header = self.table.horizontalHeader()
        for col in range(4):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
        fixed_width = 50
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(4, fixed_width)
        layout.addWidget(self.table)

        self.form_widget = QWidget()
        form_layout = QHBoxLayout(self.form_widget)

        self.input_name = QLineEdit()
        self.input_name.setPlaceholderText("Name")
        self.input_type = QComboBox()
        self.input_type.setView(QListView())
        self.variable_type_data = {}

        self.load_variable_types()

        self.input_expression = QLineEdit()
        self.input_expression.setPlaceholderText("Expression")
        self.input_description = QLineEdit()
        self.input_description.setPlaceholderText("Description")
        self.btn_add = QPushButton("➕")
        self.btn_add.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_add.clicked.connect(self.add_new_variable)
        form_layout.addWidget(self.input_name)
        form_layout.addWidget(self.input_type)
        form_layout.addWidget(self.input_expression)
        form_layout.addWidget(self.input_description)
        form_layout.addWidget(self.btn_add)
        layout.addWidget(self.form_widget)

        self.setLayout(layout)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setTextElideMode(Qt.TextElideMode.ElideNone)

        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)
        copy_action = QAction("Copy", self)
        copy_action.setShortcut("Ctrl+C")
        copy_action.triggered.connect(self.copy_selected_cells)
        self.table.addAction(copy_action)

        self.update_dynamic_fields()

    def load_variable_types(self):
        json_path = os.path.join(self.base_path, "appdata", "dynamic_variables.json")
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                types = data.get("user_variables_types", {})
                if isinstance(types, dict):

                    self.variable_type_data = types
                    self.input_type.addItems(types.keys())
                else:
                    self.input_type.addItems(types)
        except Exception:
            self.input_type.addItems(["python", "bash"])

    def copy_selected_cells(self):
        selection = self.table.selectedIndexes()
        if not selection:
            return

        selection.sort(key=lambda index: (index.row(), index.column()))

        cell_map = {}
        for index in selection:
            row = index.row()
            col = index.column()
            value = index.data()
            if row not in cell_map:
                cell_map[row] = {}
            cell_map[row][col] = str(value) if value is not None else ""

        copied_text = []
        for row in sorted(cell_map.keys()):
            cols = cell_map[row]
            line = "\t".join([cols[col] for col in sorted(cols)])
            copied_text.append(line)

        clipboard = QApplication.clipboard()
        clipboard.setText("\n".join(copied_text))

    def showEvent(self, event):
        super().showEvent(event)
        self._adjust_column_widths()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._adjust_column_widths()

    def _adjust_column_widths(self):
        header = self.table.horizontalHeader()
        total_width = self.table.viewport().width()
        fixed_width = header.sectionSize(4)
        variable_width = total_width - fixed_width
        num_variable_cols = 4
        if num_variable_cols > 0 and variable_width > 0:
            section_width = variable_width // num_variable_cols
            for col in range(num_variable_cols):
                header.resizeSection(col, section_width)

    def update_dynamic_fields(self):
        self.table.setRowCount(0)
        try:
            json_path = os.path.join(self.base_path, "appdata", "dynamic_variables.json")
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            user_vars = data.get("user_variables", [])
            self.table.setRowCount(len(user_vars))
            for row, entry in enumerate(user_vars):
                self._populate_row(row, entry)

        except Exception as e:
            self.table.setRowCount(1)
            self.table.setSpan(0, 0, 1, 5)
            self.table.setItem(0, 0, QTableWidgetItem(str(e)))

    def _populate_row(self, row, entry):
        name_item = QTableWidgetItem(entry.get("name", ""))
        type_item = QTableWidgetItem(entry.get("type", ""))
        expr_item = QTableWidgetItem(entry.get("expression", ""))
        desc_item = QTableWidgetItem(entry.get("description", ""))
        self.table.setItem(row, 0, name_item)
        self.table.setItem(row, 1, type_item)
        self.table.setItem(row, 2, expr_item)
        self.table.setItem(row, 3, desc_item)
        btn_delete = QPushButton("🗑")
        btn_delete.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        btn_delete.clicked.connect(self.handle_delete)
        self.table.setCellWidget(row, 4, btn_delete)

    def add_new_variable(self):
        def is_protected_env_var(name: str) -> bool:
            if name in os.environ:
                return True

            readonly_check = subprocess.run(
                ["bash", "-c", f"readonly -p | grep -w {name}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if readonly_check.returncode == 0:
                return True

            declare_check = subprocess.run(
                ["bash", "-c", f"declare -p {name}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            return declare_check.returncode == 0

        name = self.input_name.text().strip()
        typ = self.input_type.currentText()
        expr = self.input_expression.text().strip()
        desc = self.input_description.text().strip()

        if not name:
            QMessageBox.warning(self, "Input Error", "Name cannot be empty.")
            return

        env_var_pattern = r'^[A-Za-z_][A-Za-z0-9_]*$'
        if not re.match(env_var_pattern, name):
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setWindowTitle("Invalid Environment Variable")
            msg.setText(
                f"'{name}' is not a valid environment variable name.\n\n"
                "It must start with a letter or underscore (_) and\n"
                "contain only letters, digits, or underscores."
            )
            msg.exec()
            return

        if not expr:
            QMessageBox.warning(self, "Input Error", "Expression cannot be empty.")
            return

        if is_protected_env_var(name):
            QMessageBox.critical(
                self,
                "Protected Environment Variable",
                f"'{name}' is a protected system environment variable.\n"
                "Modifying it may break the system."
            )
            return

        for row in range(self.table.rowCount()):
            existing = self.table.item(row, 0).text() if self.table.item(row, 0) else ""
            if existing == name:
                QMessageBox.warning(self, "Input Error", f"Variable '{name}' already exists.")
                return

        row = self.table.rowCount()
        self.table.insertRow(row)

        entry = {
            "name": name,
            "type": typ,
            "expression": expr,
            "description": desc
        }

        try:
            json_path = self.c.dynamic_vars_path

            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            user_vars = data.get("user_variables", [])

            user_vars.append(entry)
            data["user_variables"] = user_vars

            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)

            self.c.load_dynamic_variables()

            self.update_dynamic_fields()
            user_vars_list = self.c.dynamic_vars.get("user_variables", [])
            names = [var.get("name") for var in user_vars_list if var.get("name")]

            for name, obj in self.c.panel_widgets.items():
                if name.endswith("dynamic_name_combo"):

                    current_text = obj.currentText()

                    obj.blockSignals(True)
                    obj.clear()
                    obj.addItems(names)

                    if current_text in names:
                        index = obj.findText(current_text)
                        if index >= 0:
                            obj.setCurrentIndex(index)

                    obj.blockSignals(False)

        except Exception as e:
            QMessageBox.critical(self, "Save Error", str(e))
            return

        self.input_name.clear()
        self.input_expression.clear()
        self.input_description.clear()

    def handle_delete(self):
        btn = self.sender()
        if not btn:
            return
        for row in range(self.table.rowCount()):
            if self.table.cellWidget(row, 4) is btn:
                var_name = self.table.item(row, 0).text()
                reply = QMessageBox.question(
                    self, "Confirm Deletion",
                    f"Are you sure you want to delete dynamic variable '{var_name}'?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.Yes:
                    try:
                        json_path = self.c.dynamic_vars_path

                        with open(json_path, "r", encoding="utf-8") as f:
                            data = json.load(f)

                        user_vars = data.get("user_variables", [])

                        user_vars = [v for v in user_vars if v.get("name") != var_name]
                        data["user_variables"] = user_vars

                        with open(json_path, "w", encoding="utf-8") as f:
                            json.dump(data, f, indent=4)

                        self.c.load_dynamic_variables()

                        self.update_dynamic_fields()

                        user_vars_list = self.c.dynamic_vars.get("user_variables", [])
                        names = [var.get("name") for var in user_vars_list if var.get("name")]

                        for name, obj in self.c.panel_widgets.items():
                            if name.endswith("dynamic_name_combo"):

                                current_text = obj.currentText()

                                obj.blockSignals(True)
                                obj.clear()
                                obj.addItems(names)

                                if current_text in names:
                                    index = obj.findText(current_text)
                                    if index >= 0:
                                        obj.setCurrentIndex(index)

                                obj.blockSignals(False)

                    except Exception as e:
                        QMessageBox.critical(self, "Delete Error", str(e))

                break
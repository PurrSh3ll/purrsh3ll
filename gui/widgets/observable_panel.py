from PyQt6.QtWidgets import (
    QWidget, QComboBox, QLabel, QLineEdit, QPushButton,
    QHBoxLayout, QVBoxLayout, QListView, QScrollArea, QSizePolicy, QMessageBox
)
from PyQt6.QtCore import Qt
import re, os, json, sys
import shutil, subprocess

class ObserverRow:
    WIDGET_KEYS = (
        "row", "type_combo", "remove_button", "confirm_button",
        "refresh_button", "name_edit", "value_edit",
        "dynamic_name_combo", "dynamic_value_label",
    )

    def __init__(self, panel: "ObserverPanel", row_id: int):
        self.panel = panel
        self.c = panel.c
        self.row_id = row_id
        self._build_widgets()
        self._register_widgets()
        self._connect_signals()
        self.on_type_changed()

    def _build_widgets(self):
        row = QWidget()
        row.setFixedHeight(ObserverPanel.ROW_HEIGHT)
        row.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        layout = QHBoxLayout(row)
        layout.setContentsMargins(6, 2, 6, 2)
        layout.setSpacing(6)
        layout.setAlignment(Qt.AlignmentFlag.AlignLeft)

        type_combo = QComboBox()
        type_combo.setView(QListView())
        type_combo.addItems(["static", "dynamic", "command"])

        remove_button = QPushButton("🗑️")
        remove_button.setFixedSize(ObserverPanel.BTN_SIZE, ObserverPanel.BTN_SIZE)

        confirm_button = QPushButton("✔")
        confirm_button.setFixedSize(ObserverPanel.BTN_SIZE, ObserverPanel.BTN_SIZE)

        refresh_button = QPushButton("↻")
        refresh_button.setFixedSize(ObserverPanel.BTN_SIZE, ObserverPanel.BTN_SIZE)
        refresh_button.setVisible(False)

        name_edit = QLineEdit()
        name_edit.setPlaceholderText("Name")
        name_edit.setFixedHeight(ObserverPanel.BTN_SIZE)
        name_edit.setFixedWidth(ObserverPanel.NAME_MIN_WIDTH)
        name_edit.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        value_edit = QLineEdit()
        value_edit.setPlaceholderText("Value")
        value_edit.setFixedHeight(ObserverPanel.BTN_SIZE)
        value_edit.setFixedWidth(ObserverPanel.VALUE_MIN_WIDTH)
        value_edit.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        user_vars_list = self.c.dynamic_vars.get("user_variables", [])
        names = [var.get("name") for var in user_vars_list if var.get("name")]
        dynamic_name_combo = QComboBox()
        dynamic_name_combo.addItems(names)
        dynamic_name_combo.setVisible(False)
        dynamic_name_combo.setFixedHeight(ObserverPanel.BTN_SIZE)

        dynamic_value_label = QLineEdit()
        dynamic_value_label.setPlaceholderText("N/A")
        dynamic_value_label.setVisible(False)
        dynamic_value_label.setFixedHeight(ObserverPanel.BTN_SIZE)
        dynamic_value_label.setReadOnly(True)
        dynamic_value_label.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        dynamic_value_label.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        dynamic_value_label.setFixedWidth(ObserverPanel.VALUE_MIN_WIDTH)

        layout.addWidget(type_combo)
        layout.addWidget(remove_button)
        layout.addWidget(confirm_button)
        layout.addWidget(refresh_button)
        layout.addWidget(name_edit)
        layout.addWidget(value_edit)
        layout.addWidget(dynamic_name_combo)
        layout.addWidget(dynamic_value_label)

        self.row = row
        self.type_combo = type_combo
        self.remove_button = remove_button
        self.confirm_button = confirm_button
        self.refresh_button = refresh_button
        self.name_edit = name_edit
        self.value_edit = value_edit
        self.dynamic_name_combo = dynamic_name_combo
        self.dynamic_value_label = dynamic_value_label

    def _register_widgets(self):
        for key_suffix in self.WIDGET_KEYS:
            self.c.panel_widgets[f"observer_row_{self.row_id}_{key_suffix}"] = getattr(self, key_suffix)

    def _unregister_widgets(self):
        for key_suffix in self.WIDGET_KEYS:
            self.c.panel_widgets.pop(f"observer_row_{self.row_id}_{key_suffix}", None)

    def _connect_signals(self):
        p = self.panel
        self.remove_button.clicked.connect(self.remove)
        self.confirm_button.clicked.connect(self.toggle_confirm)
        self.refresh_button.clicked.connect(self.toggle_refresh)
        self.type_combo.currentIndexChanged.connect(self.on_type_changed)
        self.name_edit.textChanged.connect(
            lambda: p._auto_expand_line_edit(self.name_edit, p.NAME_MIN_WIDTH, p.FIELD_MAX_WIDTH)
        )
        self.value_edit.textChanged.connect(
            lambda: p._auto_expand_line_edit(self.value_edit, p.VALUE_MIN_WIDTH, p.FIELD_MAX_WIDTH)
        )
        self.dynamic_value_label.textChanged.connect(
            lambda: p._auto_expand_line_edit(self.dynamic_value_label, p.VALUE_MIN_WIDTH, p.FIELD_MAX_WIDTH)
        )
        self.dynamic_name_combo.activated.connect(lambda: self.dynamic_value_label.setText(""))

    def _all_widgets(self):
        return {k: getattr(self, k) for k in self.WIDGET_KEYS}

    def _apply_confirm_style(self, confirmed: bool):
        value = True if confirmed else None
        for w in self._all_widgets().values():
            w.setProperty("confirmed", value)
            if w is self.row:
                continue
            w.setStyleSheet(self.panel.observable_panel_stylesheet)
        self.row.style().unpolish(self.row)
        self.row.style().polish(self.row)
        self.remove_button.setEnabled(not confirmed)

    def _apply_refresh_style(self, confirmed: bool):
        value = True if confirmed else None
        for w in self._all_widgets().values():
            w.setProperty("confirmed", value)
            w.style().unpolish(w)
            w.style().polish(w)
        self.row.setProperty("confirmed", value)
        self.row.style().unpolish(self.row)
        self.row.style().polish(self.row)
        self.remove_button.setEnabled(not confirmed)

    def remove(self):
        row_type = self.type_combo.currentText()
        name_preview = (
            self.dynamic_name_combo.currentText()
            if row_type == "dynamic"
            else self.name_edit.text().strip()
        )
        label = f"'{name_preview}'" if name_preview else "this row"
        reply = QMessageBox.question(
            self.panel,
            "Confirm Delete",
            f"Are you sure you want to remove {label}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        if self.row.property("confirmed") is True:
            name_text = self.name_edit.text().strip()
            dynamic_text = self.dynamic_name_combo.currentText()
            unset_name = dynamic_text if row_type == "dynamic" else name_text
            try:
                confirmed = [e for e in self.panel._get_confirmed_entries() if e[0] != unset_name]
                self.panel._rebuild_env_vars_file(confirmed)
                target = "all"
                self.panel._unset_silently(unset_name, row_type, target)
            except Exception:
                self._show_msg(QMessageBox.Icon.Warning, "Terminal Unset Warning",
                               "Variable removed from file, but failed to unset in terminals.")

        self._unregister_widgets()
        self.panel.rows_layout.removeWidget(self.row)
        self.row.setParent(None)
        self.row.deleteLater()

    def toggle_confirm(self):
        is_locked = self.name_edit.isReadOnly()

        if not is_locked:
            name_text = self.name_edit.text().strip()
            value_text = self.value_edit.text().strip()

            if not name_text or not value_text:
                self._show_msg(QMessageBox.Icon.Warning, "Missing Data",
                               "Both 'Name' and 'Value' fields must be filled.")
                return

            if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name_text):
                self._show_msg(QMessageBox.Icon.Warning, "Invalid Environment Variable",
                               f"'{name_text}' is not a valid environment variable name.\n\n"
                               "It must start with a letter or underscore (_) and\n"
                               "contain only letters, digits, or underscores.")
                return

            row_type = self.type_combo.currentText()

            if row_type == "command" and self.panel.is_system_command(name_text):
                self._show_msg(QMessageBox.Icon.Critical, "Protected Alias Name",
                               f"'{name_text}' cannot be used as an alias name.\n"
                               "It conflicts with an existing system command or shell builtin.")
                return

            if row_type == "static" and self.panel.is_protected_env_var(name_text):
                self._show_msg(QMessageBox.Icon.Critical, "Protected Environment Variable",
                               f"'{name_text}' is a protected system environment variable.\n"
                               "Modifying it may break the system.")
                return

            if self.panel._env_var_exists_in_file(name_text):
                label = "environment variable" if row_type == "static" else "Alias for"
                self._show_msg(QMessageBox.Icon.Warning, "Name Already Exists",
                               f"The {label} '{name_text}' already exists ")
                return

            try:
                confirmed = self.panel._get_confirmed_entries()
                confirmed.append((name_text, value_text, row_type))
                self.panel._rebuild_env_vars_file(confirmed)
                target = "all"
                self.panel._inject_silently(name_text, value_text, row_type, target)
            except Exception:
                self._show_msg(QMessageBox.Icon.Critical, "File Write Error", "Failed to write to file")
                return

            self.name_edit.setReadOnly(True)
            self.value_edit.setReadOnly(True)
            self.type_combo.setEnabled(False)
            self.confirm_button.setText("❌")
            self._apply_confirm_style(True)
        else:
            name_text = self.name_edit.text().strip()
            row_type = self.type_combo.currentText()
            try:
                confirmed = [e for e in self.panel._get_confirmed_entries() if e[0] != name_text]
                self.panel._rebuild_env_vars_file(confirmed)
                target = "all"
                self.panel._unset_silently(name_text, row_type, target)
            except Exception:
                self._show_msg(QMessageBox.Icon.Critical, "File Remove Error", "Failed to remove variable from file")
                return

            self.name_edit.setReadOnly(False)
            self.value_edit.setReadOnly(False)
            self.type_combo.setEnabled(True)
            self.confirm_button.setText("✔")
            self._apply_confirm_style(False)

    def toggle_refresh(self):
        is_active = self.refresh_button.property("confirmed") is True
        name_text = self.dynamic_name_combo.currentText()
        var_type = self.type_combo.currentText()

        if not is_active:
            if self.panel._env_var_exists_in_file(name_text):
                self._show_msg(QMessageBox.Icon.Warning, "Name Already Exists",
                               f"The environment variable '{name_text}' already exists.")
                return

            try:
                with open(self.c.dynamic_vars_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                user_vars = data.get("user_variables", [])
                entry = next((v for v in user_vars if v.get("name") == name_text), None)
                if not entry:
                    self.dynamic_value_label.setText("Failed")
                    return

                var_type = entry.get("type")
                expression = entry.get("expression")

                try:
                    if var_type == "bash":
                        result = subprocess.run(["bash", "-c", expression],
                                                capture_output=True, text=True, timeout=1)
                    elif var_type == "python":
                        result = subprocess.run([sys.executable, "-c", expression],
                                                capture_output=True, text=True, timeout=1)
                    else:
                        self.dynamic_value_label.setText("Failed")
                        return

                    output = result.stdout.strip()
                    if result.returncode != 0 or not output:
                        self.dynamic_value_label.setText("Failed")
                        return
                    self.dynamic_value_label.setText(str(output))
                except Exception as e:
                    self.dynamic_value_label.setText("Failed")
                    return

                value_text = self.dynamic_value_label.text().strip()
                confirmed = self.panel._get_confirmed_entries()
                confirmed.append((name_text, value_text, "dynamic"))
                self.panel._rebuild_env_vars_file(confirmed)
                target = "all"
                self.panel._inject_silently(name_text, value_text, "dynamic", target)

            except Exception:
                self._show_msg(QMessageBox.Icon.Critical, "Export Error", "Failed to export variable.")
                return

            self.name_edit.setReadOnly(True)
            self.value_edit.setReadOnly(True)
            self.type_combo.setEnabled(False)
            self.dynamic_name_combo.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            self.dynamic_name_combo.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
            self.refresh_button.setText("❌")
            self.refresh_button.setProperty("confirmed", True)
            self.refresh_button.setEnabled(True)
            self._apply_refresh_style(True)
        else:
            try:
                confirmed = [e for e in self.panel._get_confirmed_entries() if e[0] != name_text]
                self.panel._rebuild_env_vars_file(confirmed)
                target = "all"
                self.panel._unset_silently(name_text, "dynamic", target)
            except Exception:
                self._show_msg(QMessageBox.Icon.Warning, "Unset Warning",
                               "Variable removed from file, but failed to unset in terminals.")

            self.name_edit.setReadOnly(False)
            self.value_edit.setReadOnly(False)
            self.type_combo.setEnabled(True)
            self.dynamic_name_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
            self.dynamic_name_combo.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
            self.refresh_button.setText("↻")
            self.refresh_button.setProperty("confirmed", None)
            self.refresh_button.setEnabled(True)
            self._apply_refresh_style(False)

    def on_type_changed(self):
        is_dynamic = self.type_combo.currentText() == "dynamic"
        self.confirm_button.setVisible(not is_dynamic)
        self.refresh_button.setVisible(is_dynamic)
        self.name_edit.setVisible(not is_dynamic)
        self.value_edit.setVisible(not is_dynamic)
        self.dynamic_name_combo.setVisible(is_dynamic)
        self.dynamic_value_label.setVisible(is_dynamic)

    def _show_msg(self, icon, title, text):
        msg = QMessageBox(self.panel)
        msg.setIcon(icon)
        msg.setWindowTitle(title)
        msg.setText(text)
        msg.exec()

class ObserverPanel(QWidget):
    ROW_HEIGHT = 36
    BTN_SIZE = 28
    NAME_MIN_WIDTH = 80
    VALUE_MIN_WIDTH = 110
    FIELD_MAX_WIDTH = 400

    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.c = controller
        self.env_vars_path = self.c.sys_vars_path
        self.observer_panel_state_path = self.c.observer_panel_state_path
        self.row_counter = 0

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.c.widgets["observer_row_scroll"] = self.scroll

        self.rows_container = QWidget()
        self.rows_layout = QVBoxLayout(self.rows_container)
        self.rows_layout.setContentsMargins(0, 0, 0, 0)
        self.rows_layout.setSpacing(0)
        self.rows_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.scroll.setWidget(self.rows_container)
        main_layout.addWidget(self.scroll)

    def _env_var_exists_in_file(self, var_name):
        if not os.path.exists(self.env_vars_path):
            return False
        pattern = re.compile(rf'^\s*(export\s+|alias\s+)?{re.escape(var_name)}\s*=')
        with open(self.env_vars_path, "r") as f:
            for line in f:
                if pattern.match(line):
                    return True
        return False

    def _append_env_var_to_file(self, name, value, type=None):
        value = value.strip()
        escaped_value = value.replace('"', '\\"')
        if type == "static" or type == "dynamic":
            prefix = "export "
        elif type == "command":
            prefix = "alias "
        else:
            prefix = ""
        line = f'{prefix}{name}="{escaped_value}"\n'
        if os.path.exists(self.env_vars_path):
            with open(self.env_vars_path, "rb+") as f:
                f.seek(0, os.SEEK_END)
                if f.tell() > 0:
                    f.seek(-1, os.SEEK_END)
                    if f.read(1) != b"\n":
                        f.write(b"\n")
        with open(self.env_vars_path, "a") as f:
            f.write(line)

    def _auto_expand_line_edit(self, edit, min_width, max_width=None, type=None):
        fm = edit.fontMetrics()
        text = edit.text() or edit.placeholderText()
        text_width = fm.horizontalAdvance(text) + 20
        target = max(min_width, text_width)
        if max_width:
            target = min(target, max_width)
        if target > edit.width():
            edit.setFixedWidth(target)

    def _remove_env_var_from_file(self, var_name, type=None):
        if not os.path.exists(self.env_vars_path):
            return
        pattern = re.compile(rf'^\s*(export\s+|alias\s+)?{re.escape(var_name)}\s*=')
        try:
            with open(self.env_vars_path, "r") as f:
                lines = f.readlines()
            with open(self.env_vars_path, "w") as f:
                for line in lines:
                    if not pattern.match(line):
                        f.write(line)
        except Exception as e:
            raise e

    def _send_to_terminals(self, cmd, target="all"):
        wrapped = f"{cmd}\n"
        if target == "current":
            tabs = self.c.widgets["terminal_tabs"]
            current_term = self.c.wrapper_to_console.get(tabs.currentWidget())
            if current_term:
                current_term.sendText(wrapped)
            return
        for term in self.c.terminals.values():
            term.sendText(wrapped)

    def _get_confirmed_entries(self):
        # Build row_widget → row_id map via panel_widgets
        row_to_id = {}
        for key, widget in self.c.panel_widgets.items():
            if key.startswith("observer_row_") and key.endswith("_row"):
                parts = key.split("_")
                if len(parts) >= 3:
                    row_to_id[id(widget)] = parts[2]

        result = []
        for i in range(self.rows_layout.count()):
            row_widget = self.rows_layout.itemAt(i).widget()
            if row_widget is None:
                continue
            row_id = row_to_id.get(id(row_widget))
            if row_id is None:
                continue
            type_combo = self.c.panel_widgets.get(f"observer_row_{row_id}_type_combo")
            name_edit = self.c.panel_widgets.get(f"observer_row_{row_id}_name_edit")
            value_edit = self.c.panel_widgets.get(f"observer_row_{row_id}_value_edit")
            refresh_button = self.c.panel_widgets.get(f"observer_row_{row_id}_refresh_button")
            dynamic_name_combo = self.c.panel_widgets.get(f"observer_row_{row_id}_dynamic_name_combo")
            dynamic_value_label = self.c.panel_widgets.get(f"observer_row_{row_id}_dynamic_value_label")
            if not type_combo:
                continue
            row_type = type_combo.currentText()
            if row_type == "dynamic":
                if refresh_button and refresh_button.property("confirmed") is True:
                    name = dynamic_name_combo.currentText() if dynamic_name_combo else ""
                    value = dynamic_value_label.text().strip() if dynamic_value_label else ""
                    if name:
                        result.append((name, value, "dynamic"))
            else:
                if name_edit and name_edit.isReadOnly():
                    name = name_edit.text().strip()
                    value = value_edit.text().strip() if value_edit else ""
                    if name:
                        result.append((name, value, row_type))
        return result

    def _rebuild_env_vars_file(self, entries):
        prev_vars, prev_aliases = set(), set()
        if os.path.exists(self.env_vars_path):
            with open(self.env_vars_path, "r", encoding="utf-8") as f:
                for line in f:
                    m = re.match(r'^# PURRSH_VARS:\s*(.*)', line)
                    if m:
                        prev_vars = set(m.group(1).split(',')) - {''}
                    m = re.match(r'^# PURRSH_ALIASES:\s*(.*)', line)
                    if m:
                        prev_aliases = set(m.group(1).split(',')) - {''}
        curr_vars = {n for n, v, t in entries if t != "command"}
        curr_aliases = {n for n, v, t in entries if t == "command"}
        all_vars = prev_vars | curr_vars
        all_aliases = prev_aliases | curr_aliases
        lines = ["# PurrSh3ll managed variables - auto-generated\n"]
        if all_vars:
            lines.append(f"# PURRSH_VARS: {','.join(sorted(all_vars))}\n")
            lines.append(f"unset {' '.join(sorted(all_vars))} 2>/dev/null\n")
        if all_aliases:
            lines.append(f"# PURRSH_ALIASES: {','.join(sorted(all_aliases))}\n")
            lines.append(f"unalias {' '.join(sorted(all_aliases))} 2>/dev/null\n")
        for name, value, row_type in entries:
            escaped = value.replace('"', '\\"')
            if row_type == "command":
                lines.append(f'alias {name}="{escaped}"\n')
            else:
                lines.append(f'export {name}="{escaped}"\n')
        with open(self.env_vars_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

    def _write_to_fifos(self, cmd, target="all"):
        if not hasattr(self.c, 'terminal_fifos'):
            return
        encoded = (cmd + "\n").encode()
        if target == "current":
            try:
                tabs = self.c.widgets["terminal_tabs"]
                current_term = self.c.wrapper_to_console.get(tabs.currentWidget())
                if current_term:
                    for tid, t in self.c.terminals.items():
                        if t is current_term:
                            fifo_info = self.c.terminal_fifos.get(tid)
                            if fifo_info:
                                try:
                                    os.write(fifo_info[1], encoded)
                                except Exception:
                                    pass
                            break
            except Exception:
                pass
            return
        for fifo_info in self.c.terminal_fifos.values():
            try:
                os.write(fifo_info[1], encoded)
            except Exception:
                pass

    def _inject_silently(self, name, value, row_type, target="all"):
        escaped = value.replace('"', '\\"')
        if row_type == "command":
            cmd = f'alias {name}="{escaped}"'
        else:
            cmd = f'export {name}="{escaped}"'
        self._write_to_fifos(cmd, target)

    def _unset_silently(self, name, row_type, target="all"):
        if row_type == "command":
            cmd = f'unalias {name} 2>/dev/null'
        else:
            cmd = f'unset {name} 2>/dev/null'
        self._write_to_fifos(cmd, target)

    def get_all_rows_data(self):
        data = []
        for i in range(self.rows_layout.count()):
            row_widget = self.rows_layout.itemAt(i).widget()
            for key, widget in self.c.panel_widgets.items():
                if widget is row_widget:
                    row_id = key.split("_")[2]
                    name_edit = self.c.panel_widgets.get(f"observer_row_{row_id}_name_edit")
                    dynamic_name_combo = self.c.panel_widgets.get(f"observer_row_{row_id}_dynamic_name_combo")
                    value_edit = self.c.panel_widgets.get(f"observer_row_{row_id}_value_edit")
                    type_combo = self.c.panel_widgets.get(f"observer_row_{row_id}_type_combo")
                    if not type_combo:
                        continue
                    current_type = type_combo.currentText()
                    name_value = (dynamic_name_combo.currentText()
                                  if current_type == "dynamic" and dynamic_name_combo
                                  else (name_edit.text() if name_edit else ""))
                    if value_edit:
                        data.append({
                            "row_id": row_id,
                            "type": current_type,
                            "name": name_value,
                            "value": value_edit.text(),
                            "confirmed": row_widget.property("confirmed"),
                        })
        return data

    def save_state_to_file(self):
        try:
            os.makedirs(os.path.dirname(self.observer_panel_state_path), exist_ok=True) \
                if os.path.dirname(self.observer_panel_state_path) else None
            if self.c.save_system_vars:
                rows_data = self.get_all_rows_data()
                state = {"row_count": len(rows_data), "rows": rows_data}
                with open(self.observer_panel_state_path, "w", encoding="utf-8") as f:
                    json.dump(state, f, indent=4)
            else:
                with open(self.observer_panel_state_path, "w", encoding="utf-8") as f:
                    f.write("")
        except Exception as e:
            pass

    def is_system_command(self, name: str) -> bool:
        if shutil.which(name) is not None:
            return True
        result = subprocess.run(["bash", "-c", f"type {name}"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.returncode == 0

    def is_protected_env_var(self, name: str) -> bool:
        return name in os.environ

    def create_row(self):
        self.row_counter += 1
        obs_row = ObserverRow(self, self.row_counter)
        self.rows_layout.insertWidget(0, obs_row.row)

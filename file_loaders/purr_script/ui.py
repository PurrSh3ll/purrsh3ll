import os, re, json
from datetime import datetime
from pathlib import Path

from PyQt6.QtGui import QIntValidator, QFont, QDesktopServices
from PyQt6.QtCore import QUrl, Qt
from PyQt6.QtCore import QThread
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QSizePolicy,
    QPlainTextEdit, QTextEdit, QLabel, QCheckBox, QFrame,
    QLineEdit, QComboBox, QStackedLayout, QScrollArea
)

from gui.panels.history_script_wdg import HistoryScriptWdg
from gui.panels.favorites_script_wdg import FavScriptWdg

class UIMixin:
    def _build_ui(self):

        def _split_ampersand(cmd: str):
            if cmd is None:
                return "", False

            cleaned = cmd.rstrip()

            if cleaned.endswith("&"):
                core = cleaned[:-1].rstrip()
                return core, True

            return cleaned, False

        def _join_ampersand(core: str, has_amp: bool) -> str:
            core = core.rstrip()
            return (core + " &") if has_amp else core

        def _remove_output_redirect(cmd: str) -> str:
            core, has_amp = _split_ampersand(cmd)

            core = re.sub(r'\s+>\s+\S+$', '', core)

            return _join_ampersand(core, has_amp)

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(6, 6, 6, 6)
        root_layout.setSpacing(6)
        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(6)
        self.info_field = QPlainTextEdit(parent=self)
        self.info_field.setReadOnly(True)
        self.info_field.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        info_text = ""
        self.info_field.setPlainText(info_text)
        line_count = info_text.count("\n") + 1
        line_height = self.info_field.fontMetrics().height()
        self.info_field.setFixedHeight(line_height * line_count + 12)
        self.info_field.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.install_btn = QPushButton("Install", parent=self)
        self.install_btn.setFixedHeight(28)
        self.install_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.install_btn.setEnabled(False)
        self.install_btn.clicked.connect(self._on_install_clicked)
        top_row.addWidget(self.info_field, 1)
        top_row.addWidget(self.install_btn, 0, Qt.AlignmentFlag.AlignTop)
        root_layout.addLayout(top_row)
        buttons_row = QHBoxLayout()
        buttons_row.setContentsMargins(0, 0, 0, 0)
        buttons_row.setSpacing(6)

        self.favorite_button = QPushButton("favorite", parent=self)
        self.help_button = QPushButton("help", parent=self)
        self.docs_button = QPushButton("docs", parent=self)
        self.readme_button = QPushButton("readme", parent=self)
        self.history_button = QPushButton("history", parent=self)
        self.notes_button = QPushButton("notes", parent=self)
        self.code_button = QPushButton("code", parent=self)
        self.buttons = [self.favorite_button, self.help_button, self.docs_button, self.readme_button,
                         self.history_button, self.notes_button, self.code_button]
        checkable_names = {"favorite","help", "docs", "readme", "history", "notes", "code"}
        for button in self.buttons:
            button.setFixedHeight(28)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

            if button.text() in checkable_names:
                button.setCheckable(True)
                button.clicked.connect(lambda checked, b=button: self._on_checkable_clicked(b))
            else:
                button.setCheckable(False)

            buttons_row.addWidget(button)

        root_layout.addLayout(buttons_row)

        self.central_container = QWidget(self)
        self.central_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.central_layout = QVBoxLayout(self.central_container)
        self.central_layout.setContentsMargins(0, 0, 0, 0)
        self.central_layout.setSpacing(0)

        self.central_stack = QStackedLayout()

        self.welcome_field = QPlainTextEdit()
        self.welcome_field.setReadOnly(True)
        self.ascii_title = self._make_ascii_title().rstrip("\n")
        font = QFont("Monospace", 8)
        self.welcome_field.setFont(font)
        self.welcome_field.setPlainText(self.ascii_title)

        self.detail_field = QTextEdit()
        self.detail_field.setReadOnly(True)
        self.detail_field.setObjectName("docs")
        self.detail_field.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.detail_field.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.help_field = QTextEdit()
        self.help_field.setReadOnly(True)
        self.help_field.setObjectName("docs")
        self.help_field.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.help_field.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.docs_field = QTextEdit()
        self.docs_field.setReadOnly(True)
        self.docs_field.setObjectName("docs")
        self.docs_field.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.docs_field.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.readme_field = QTextEdit()
        self.readme_field.setReadOnly(True)
        self.readme_field.setObjectName("docs")
        self.readme_field.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.readme_field.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.favorite_field = FavScriptWdg(fav_path=self.script_favorite_path, parent=self.central_container, main_script = self)
        self.history_field = HistoryScriptWdg(hist_path= self.script_history_path, fav_path=self.script_favorite_path,
                                              parent=self.central_container, fav_obj = self.favorite_field)

        self.notes_field = QTextEdit()
        self.notes_field.setReadOnly(False)
        self.notes_field.setObjectName("docs")
        self.notes_field.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.notes_field.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.notes_field.textChanged.connect(lambda: self._notes_save_timer.start(500))
        self.notes_field.textChanged.connect(self._save_notes_to_file)

        self.central_layout.addLayout(self.central_stack, 1)
        root_layout.addWidget(self.central_container, 1)
        self.central_stack.addWidget(self.welcome_field)
        self.central_stack.addWidget(self.favorite_field)
        self.central_stack.addWidget(self.help_field)
        self.central_stack.addWidget(self.docs_field)
        self.central_stack.addWidget(self.readme_field)
        self.central_stack.addWidget(self.history_field)
        self.central_stack.addWidget(self.notes_field)

        self.central_stack.setCurrentWidget(self.welcome_field)

        sep1 = QFrame(self)
        sep1.setFrameShape(QFrame.Shape.HLine)
        sep1.setFrameShadow(QFrame.Shadow.Sunken)
        sep1.setObjectName("line")
        root_layout.addWidget(sep1)
        row1 = QHBoxLayout()
        row1.setContentsMargins(0, 0, 0, 0)
        row1.setSpacing(12)
        lbl_interpreter = QLabel("Interpreter", parent=self)
        self.cmb_interpreter = QComboBox(parent=self)
        row1.addWidget(lbl_interpreter)
        row1.addWidget(self.cmb_interpreter)
        self.btn_refresh_interpreter = QPushButton("↺", parent=self)
        self.btn_refresh_interpreter.setFixedWidth(32)
        self.btn_refresh_interpreter.setToolTip("Refresh interpreter list")
        row1.addWidget(self.btn_refresh_interpreter)

        def _make_output_redirect(filename: str) -> str:
            filename = filename.strip()
            if not filename:
                filename = f"{self.name}.log"
            return f" > {filename}"

        def add_output_redirect(checked: bool):
            current_cmd = self.terminal_input.toPlainText()

            core, has_amp = _split_ampersand(current_cmd)

            if checked:
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                default_filename = f"{self.name}_{timestamp}.txt"
                self.txt_save_output.setText(default_filename)

                self.txt_save_output.setVisible(True)

                core = _remove_output_redirect(core)

                redirect = _make_output_redirect(default_filename)
                new_cmd = core.strip() + redirect

                new_cmd = _join_ampersand(new_cmd, has_amp)
                self.terminal_input.setPlainText(new_cmd)

            else:
                self.txt_save_output.setVisible(False)

                core = _remove_output_redirect(core)
                new_cmd = _join_ampersand(core, has_amp)
                self.terminal_input.setPlainText(new_cmd)

        def update_output_from_text():
            if not self.chk_save_output.isChecked():
                return

            current_cmd = self.terminal_input.toPlainText()

            core, has_amp = _split_ampersand(current_cmd)

            core = _remove_output_redirect(core)

            redirect = _make_output_redirect(self.txt_save_output.text())
            new_cmd = core.strip() + redirect

            new_cmd = _join_ampersand(new_cmd, has_amp)
            self.terminal_input.setPlainText(new_cmd)

        lbl_save = QLabel("Save Output", parent=self)
        self.chk_save_output = QCheckBox(parent=self)
        self.txt_save_output = QLineEdit(parent=self)
        self.txt_save_output.setMinimumWidth(300)

        self.chk_save_output.toggled.connect(add_output_redirect)
        self.txt_save_output.textChanged.connect(update_output_from_text)

        self.txt_save_output.setVisible(False)

        row1.addWidget(lbl_save)
        row1.addWidget(self.chk_save_output)
        row1.addWidget(self.txt_save_output, stretch=1)

        row1.addStretch(1)
        root_layout.addLayout(row1)
        row2 = QHBoxLayout()
        row2.setContentsMargins(0, 0, 0, 0)
        row2.setSpacing(12)

        def _remove_background_flag(cmd: str) -> str:
            if not cmd:
                return cmd
            return re.sub(r'\s*&\s*$', '', cmd)

        def _add_background_flag(cmd: str) -> str:
            cmd = cmd.rstrip()
            return cmd + " &"

        def update_background_flag(checked: bool):
            current_cmd = self.terminal_input.toPlainText()

            base_cmd = _remove_background_flag(current_cmd)

            if checked:
                new_cmd = _add_background_flag(base_cmd)
            else:
                new_cmd = base_cmd

            self.terminal_input.setPlainText(new_cmd)

        lbl_bg = QLabel("Background", parent=self)
        self.chk_run_in_background = QCheckBox(parent=self)
        self.chk_run_in_background.toggled.connect(update_background_flag)
        row2.addWidget(lbl_bg)
        row2.addWidget(self.chk_run_in_background)

        lbl_external = QLabel("External Terminal", parent=self)
        self.chk_run_external = QCheckBox(parent=self)
        row2.addWidget(lbl_external)
        row2.addWidget(self.chk_run_external)

        def _on_external_toggled(checked):
            if checked:
                self.chk_run_current.setChecked(False)

        self.chk_run_external.toggled.connect(_on_external_toggled)

        lbl_run_current = QLabel("Keep Session", parent=self)
        self.chk_run_current = QCheckBox(parent=self)
        row2.addWidget(lbl_run_current)
        row2.addWidget(self.chk_run_current)

        def _on_current_toggled(checked):
            if checked:
                self.chk_run_external.setChecked(False)

        self.chk_run_current.toggled.connect(_on_current_toggled)

        def _remove_sudo_prefix(cmd: str) -> str:
            if not cmd:
                return ""

            if getattr(self, "chk_root_priv", None) and self.chk_root_priv.isChecked():
                return cmd.strip()

            return re.sub(r'^\s*sudo\b\s*', '', cmd, flags=re.IGNORECASE).strip()

        def _make_sudo_prefix() -> str:
            return "sudo "

        def add_sudo_prefix(checked: bool):
            current_cmd = self.terminal_input.toPlainText() or ""

            core, has_amp = _split_ampersand(current_cmd)
            core = core or ""

            if checked:
                if _has_sudo_prefix(core):
                    new_core = core.strip()
                else:
                    core_no_sudo = _remove_sudo_prefix(core)
                    new_core = (_make_sudo_prefix() + core_no_sudo).strip()
            else:
                raw = getattr(self, "_last_raw_input", None) or current_cmd
                m = re.search(r'\bnice\s+-n\s+(-?\d+)\b', raw or "", flags=re.IGNORECASE)
                if m:
                    try:
                        level = int(m.group(1))
                    except ValueError:
                        level = None
                    if level is not None and -20 <= level <= -1:
                        new_core = core.strip()
                    else:
                        new_core = _remove_sudo_prefix(core)
                else:
                    new_core = _remove_sudo_prefix(core)

            new_cmd = _join_ampersand(new_core, has_amp)
            self.terminal_input.setPlainText(new_cmd)

        root_lbl = QLabel("Root", parent=self)
        self.chk_root_priv = QCheckBox(parent=self)
        row2.addWidget(root_lbl)
        row2.addWidget(self.chk_root_priv)

        self.chk_root_priv.toggled.connect(add_sudo_prefix)

        lbl_show_adv = QLabel("Advanced", parent=self)
        self.chk_show_advanced = QCheckBox(parent=self)
        row2.addWidget(lbl_show_adv)
        row2.addWidget(self.chk_show_advanced)

        row2.addStretch(1)
        root_layout.addLayout(row2)
        sep2 = QFrame(self)
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setFrameShadow(QFrame.Shadow.Sunken)
        sep2.setObjectName("line")
        root_layout.addWidget(sep2)
        self.advanced_widget = QWidget(parent=self)
        adv_layout = QVBoxLayout(self.advanced_widget)
        adv_layout.setContentsMargins(0, 0, 0, 0)
        adv_layout.setSpacing(6)
        row3 = QHBoxLayout()
        row3.setContentsMargins(0, 0, 0, 0)
        row3.setSpacing(12)

        priority_levels = ["Critical", "High", "Normal", "Low", "Lowest"]
        priority_levels_dict = {"Critical": -20, "High": -10, "Normal": 0, "Low": 10, "Lowest": 19}
        lbl_priority = QLabel("Priority", parent=self)
        self.cmb_priority = QComboBox(parent=self)
        self.cmb_priority.addItems(priority_levels)
        self.cmb_priority.setCurrentText("Normal")
        row3.addWidget(lbl_priority)
        row3.addWidget(self.cmb_priority)

        priority_levels_dict = {"Critical": -20, "High": -10, "Normal": 0, "Low": 10, "Lowest": 19}

        def _make_nice_prefix_from_label(label: str) -> str:
            val = priority_levels_dict.get(label, 0)
            if val == 0:
                return ""
            return f"nice -n {val} "

        def _extract_timeout_prefix(cmd: str):
            if not cmd:
                return "", ""
            m = re.match(r'^\s*(timeout\s+\S+\s+)', cmd, flags=re.IGNORECASE)
            if m:
                prefix = m.group(1)
                rest = cmd[len(prefix):]
                return prefix, rest
            return "", cmd

        def _extract_output_redirect_at_end(cmd: str):
            if not cmd:
                return "", ""
            m = re.search(r'(\s+>\s+\S+)\s*$', cmd)
            if m:
                redirect = m.group(1)
                core = cmd[:m.start(1)]
                return core.rstrip(), redirect
            return cmd, ""

        def _has_sudo_prefix(cmd: str) -> bool:
            if not cmd:
                return False
            return bool(re.match(r'^\s*sudo\b', cmd, flags=re.IGNORECASE))

        def _ensure_sudo_prefix(cmd: str) -> str:
            if not cmd:
                return cmd
            if _has_sudo_prefix(cmd):
                return cmd.strip()
            return ("sudo " + cmd).strip()

        def _remove_any_nice(cmd: str) -> str:
            if not cmd:
                return ""
            cleaned = re.sub(r'\bnice\s+-n\s+-?\d+\b\s*', '', cmd, flags=re.IGNORECASE)
            cleaned = re.sub(r'\s+', ' ', cleaned).strip()
            return cleaned

        def _rebuild_command_from_widgets():
            raw = self.terminal_input.toPlainText() or ""
            core_with_possible_nice, has_amp = _split_ampersand(raw)

            core_no_nice = _remove_any_nice(core_with_possible_nice)

            base_no_redirect, existing_redirect = _extract_output_redirect_at_end(core_no_nice)

            base_no_timeout = _remove_any_timeout(base_no_redirect)

            priority_label = self.cmb_priority.currentText() if hasattr(self, "cmb_priority") else "Normal"
            nice_prefix = _make_nice_prefix_from_label(priority_label)

            need_sudo = priority_label in ("Critical", "High")

            base_core = (base_no_timeout or "").strip()
            if base_core:
                if need_sudo:
                    base_core = _ensure_sudo_prefix(base_core)
                else:
                    base_core = _remove_sudo_prefix(base_core)

            timeout_prefix_to_use = ""
            if getattr(self, "chk_set_timeout", None) and self.chk_set_timeout.isChecked():
                secs = (self.txt_timeout.text() or "").strip()
                if not secs:
                    secs = "300"
                if re.fullmatch(r'\d+', secs):
                    timeout_prefix_to_use = f"timeout {secs}s "
                else:
                    timeout_prefix_to_use = f"timeout {secs} "

            redirect_to_use = ""
            if getattr(self, "chk_save_output", None) and self.chk_save_output.isChecked():
                fn = (self.txt_save_output.text() or "").strip()
                if not fn:
                    fn = f"{self.name}.log"
                redirect_to_use = f" > {fn}"

            m_sudo_nohup = re.match(r'^\s*(sudo\b(?:\s+[^\s]+)*)\s+nohup\b\s*(.*)', base_core, flags=re.IGNORECASE)
            if m_sudo_nohup:
                sudo_block = m_sudo_nohup.group(1).strip()
                rest_after_nohup = (m_sudo_nohup.group(2) or "").lstrip()

                parts = [sudo_block + " ", "nohup "]
                if timeout_prefix_to_use:
                    parts.append(timeout_prefix_to_use.strip() + " ")
                if nice_prefix:
                    parts.append(nice_prefix.strip() + " ")
                parts.append(rest_after_nohup)
                new_cmd = "".join(parts).strip()
            else:
                m_nohup = re.match(r'^\s*nohup\b\s*(.*)', base_core, flags=re.IGNORECASE)
                if m_nohup:
                    rest_after_nohup = (m_nohup.group(1) or "").lstrip()
                    parts = ["nohup "]
                    if timeout_prefix_to_use:
                        parts.append(timeout_prefix_to_use.strip() + " ")
                    if nice_prefix:
                        parts.append(nice_prefix.strip() + " ")
                    parts.append(rest_after_nohup)
                    new_cmd = "".join(parts).strip()
                else:
                    m = re.match(r'^(\s*sudo\b\s+)(.*)', base_core, flags=re.IGNORECASE)
                    if m:
                        sudo_part = m.group(1).strip() + " "
                        rest_cmd = (m.group(2) or "").lstrip()
                        parts = [sudo_part]
                        if timeout_prefix_to_use:
                            parts.append(timeout_prefix_to_use.strip() + " ")
                        if nice_prefix:
                            parts.append(nice_prefix.strip() + " ")
                        parts.append(rest_cmd)
                        new_cmd = "".join(parts).strip()
                    else:
                        parts = []
                        if timeout_prefix_to_use:
                            parts.append(timeout_prefix_to_use.strip() + " ")
                        if nice_prefix:
                            parts.append(nice_prefix.strip() + " ")
                        parts.append(base_core)
                        new_cmd = "".join(parts).strip()

            if redirect_to_use:
                new_cmd = new_cmd + redirect_to_use

            has_bg_widget = getattr(self, "chk_run_in_background", None) and self.chk_run_in_background.isChecked()
            final_has_amp = has_bg_widget if getattr(self, "chk_run_in_background", None) else has_amp

            return _join_ampersand(new_cmd, final_has_amp)

        def _on_priority_changed(_new_text):
            new_cmd = _rebuild_command_from_widgets()
            cur = (self.terminal_input.toPlainText() or "").strip()
            if new_cmd.strip() != cur:
                self.terminal_input.setPlainText(new_cmd)

        self.cmb_priority.currentTextChanged.connect(_on_priority_changed)

        def _remove_any_nohup(cmd: str) -> str:
            if not cmd:
                return ""
            cleaned = re.sub(r'\bnohup\b\s*', '', cmd, flags=re.IGNORECASE)
            cleaned = re.sub(r'\s+', ' ', cleaned).strip()
            return cleaned

        def _make_nohup_prefix() -> str:
            return "nohup "

        def _insert_nohup_after_sudo(core: str) -> str:
            if not core:
                return _make_nohup_prefix().strip()

            m = re.match(r'^(sudo\b[^\S\r\n]*)', core, flags=re.IGNORECASE)
            if m:
                sudo_block = m.group(1)
                rest = core[len(sudo_block):].lstrip()
                return f"{sudo_block}nohup {rest}".strip()

            return f"nohup {core}".strip()

        def add_detach_command(checked: bool):
            current_cmd = self.terminal_input.toPlainText() or ""

            core, has_amp = _split_ampersand(current_cmd)

            if checked:
                core_no_nohup = _remove_any_nohup(core)
                new_core = _insert_nohup_after_sudo(core_no_nohup)
            else:
                new_core = _remove_any_nohup(core)

            new_cmd = _join_ampersand(new_core, has_amp)
            self.terminal_input.setPlainText(new_cmd)

        lbl_detach = QLabel("Detach Terminal", parent=self)
        self.chk_detach_terminal = QCheckBox(parent=self)
        row3.addWidget(lbl_detach)
        row3.addWidget(self.chk_detach_terminal)

        self.chk_detach_terminal.toggled.connect(add_detach_command)

        def _remove_any_timeout(cmd: str) -> str:
            if not cmd:
                return ""
            cleaned = re.sub(r'\btimeout\s+\S+\s*', '', cmd, flags=re.IGNORECASE)
            cleaned = re.sub(r'\s+', ' ', cleaned).strip()
            return cleaned

        def _make_timeout_prefix(seconds_text: str) -> str:
            secs = (seconds_text or "").strip()
            if not secs:
                secs = "300"
            if re.fullmatch(r'\d+', secs):
                return f"timeout {secs}s "
            else:
                return f"timeout {secs} "

        def add_timeout(checked: bool):
            current_cmd = self.terminal_input.toPlainText() if self.terminal_input else ""
            if checked:
                self.txt_timeout.setVisible(True)

                base_cmd = _remove_any_timeout(current_cmd)
                prefix = _make_timeout_prefix(self.txt_timeout.text())

                m_sudo_nohup = re.match(r'^\s*(sudo\b(?:\s+[^\s]+)*)\s+nohup\b\s*(.*)', base_cmd, flags=re.IGNORECASE)
                if m_sudo_nohup:
                    sudo_block = m_sudo_nohup.group(1)
                    rest = m_sudo_nohup.group(2)
                    new_cmd = (sudo_block + " " + "nohup " + prefix + rest.lstrip()).strip()
                    self.terminal_input.setPlainText(new_cmd)
                    return

                m_nohup = re.match(r'^(\s*nohup\b\s+)(.*)', base_cmd, flags=re.IGNORECASE)
                if m_nohup:
                    nohup_part = m_nohup.group(1)
                    rest = m_nohup.group(2)
                    new_cmd = (nohup_part + prefix + rest.lstrip()).strip()
                    self.terminal_input.setPlainText(new_cmd)
                    return

                m = re.match(r'^(\s*sudo\b\s+)(.*)', base_cmd, flags=re.IGNORECASE)
                if m:
                    sudo_part = m.group(1)
                    rest = m.group(2)
                    new_cmd = (sudo_part + prefix + rest.lstrip()).strip()
                else:
                    new_cmd = (prefix + base_cmd.lstrip()).strip()

                self.terminal_input.setPlainText(new_cmd)

            else:
                self.txt_timeout.setVisible(False)
                new_cmd = _remove_any_timeout(current_cmd)
                self.terminal_input.setPlainText(new_cmd.strip())

        def update_timeout_from_text():
            if not getattr(self, "chk_set_timeout", None):
                return

            if self.chk_set_timeout.isChecked():
                current_cmd = self.terminal_input.toPlainText()
                base_cmd = _remove_any_timeout(current_cmd)
                prefix = _make_timeout_prefix(self.txt_timeout.text())

                m_sudo_nohup = re.match(r'^\s*(sudo\b(?:\s+[^\s]+)*)\s+nohup\b\s*(.*)', base_cmd, flags=re.IGNORECASE)
                if m_sudo_nohup:
                    sudo_block = m_sudo_nohup.group(1)
                    rest = m_sudo_nohup.group(2)
                    new_cmd = (sudo_block + " " + "nohup " + prefix + rest.lstrip()).strip()
                    self.terminal_input.setPlainText(new_cmd)
                    return

                m_nohup = re.match(r'^(\s*nohup\b\s+)(.*)', base_cmd, flags=re.IGNORECASE)
                if m_nohup:
                    nohup_part = m_nohup.group(1)
                    rest = m_nohup.group(2)
                    new_cmd = (nohup_part + prefix + rest.lstrip()).strip()
                    self.terminal_input.setPlainText(new_cmd)
                    return

                m = re.match(r'^(\s*sudo\b\s+)(.*)', base_cmd, flags=re.IGNORECASE)
                if m:
                    sudo_part = m.group(1)
                    rest = m.group(2)
                    new_cmd = (sudo_part + prefix + rest.lstrip()).strip()
                else:
                    new_cmd = (prefix + base_cmd.lstrip()).strip()

                self.terminal_input.setPlainText(new_cmd)

        lbl_timeout = QLabel("Timeout", parent=self)
        self.chk_set_timeout = QCheckBox(parent=self)
        self.txt_timeout = QLineEdit(parent=self)
        self.txt_timeout.setValidator(QIntValidator(0, 999999, parent=self))
        self.txt_timeout.setText("300")
        self.txt_timeout.setVisible(False)
        self.chk_set_timeout.toggled.connect(add_timeout)
        self.txt_timeout.textChanged.connect(update_timeout_from_text)

        row3.addWidget(lbl_timeout)
        row3.addWidget(self.chk_set_timeout)
        row3.addWidget(self.txt_timeout)
        row3.addStretch(1)
        adv_layout.addLayout(row3)

        sep3 = QFrame(self.advanced_widget)
        sep3.setFrameShape(QFrame.Shape.HLine)
        sep3.setFrameShadow(QFrame.Shadow.Sunken)
        sep3.setObjectName("line")
        adv_layout.addWidget(sep3)
        self.advanced_widget.setVisible(False)
        root_layout.addWidget(self.advanced_widget)
        self.chk_show_advanced.toggled.connect(self.advanced_widget.setVisible)
        bottom_row = QHBoxLayout()
        bottom_row.setContentsMargins(0, 0, 0, 0)
        bottom_row.setSpacing(6)

        self.terminal_input = QPlainTextEdit(self)
        self.terminal_input.setObjectName("script_term")
        self.terminal_input.setFixedHeight(36)
        self.terminal_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        bottom_row.addWidget(self.terminal_input)

        enter_btn = QPushButton("⏎", self)
        enter_btn.setFixedSize(40, 36)
        paste_btn = QPushButton("⧉", self)
        paste_btn.setFixedSize(60, 36)
        enter_btn.clicked.connect(lambda: self._execute_command((self.terminal_input.toPlainText() or "") + "\n"))
        paste_btn.clicked.connect(lambda: self._execute_command(self.terminal_input.toPlainText() or ""))
        bottom_row.addWidget(enter_btn)
        bottom_row.addWidget(paste_btn)
        root_layout.addLayout(bottom_row)

        def populate_interpreter_cmb(file_path):
            self.cmb_interpreter.clear()
            if not file_path or not os.path.exists(file_path):
                self.cmb_interpreter.addItem("Searching Python")
                self.cmb_interpreter.setEnabled(False)
                return
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                self.cmb_interpreter.addItem("Searching Python")
                self.cmb_interpreter.setEnabled(False)
                return
            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list):
                self.cmb_interpreter.addItem("Searching Python")
                self.cmb_interpreter.setEnabled(False)
                return
            seen = set()
            paths = []
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                path = entry.get("path")
                if not path:
                    continue
                path = str(path).strip()
                if not path or path in seen:
                    continue
                seen.add(path)
                paths.append(path)
            if not paths:
                self.cmb_interpreter.addItem("Searching Python")
                self.cmb_interpreter.setEnabled(False)
                return
            self.cmb_interpreter.addItems(paths)
            self.cmb_interpreter.setCurrentIndex(0)
            self.cmb_interpreter.setEnabled(True)
            update_bottom_text()
            self.update_imports_info()

        def populate_interpreter_cmb_in_thread():
            from file_loaders.purr_script.launcher import VenvWorker as _VenvWorker
            previous_interpreter = self.cmb_interpreter.currentText()

            self.thread = QThread()
            self.worker = _VenvWorker(self, controller=self.controller)
            self.worker.moveToThread(self.thread)

            self.thread.started.connect(self.worker.run)
            self.worker.finished.connect(self.thread.quit)
            self.worker.finished.connect(self.worker.deleteLater)
            self.thread.finished.connect(self.thread.deleteLater)

            def restore_previous_interpreter():
                populate_interpreter_cmb(self.controller.interpreters_json)
                self.btn_refresh_interpreter.setEnabled(True)

                index = self.cmb_interpreter.findText(previous_interpreter)
                if index != -1:
                    self.cmb_interpreter.setCurrentIndex(index)
                else:
                    self.cmb_interpreter.setCurrentIndex(0)
                self.btn_refresh_interpreter.setText("↺")
                self.btn_refresh_interpreter.setFixedWidth(32)

            self.worker.finished.connect(restore_previous_interpreter)

            self.thread.start()

        def on_refresh_clicked():
            self.btn_refresh_interpreter.setEnabled(False)
            self.btn_refresh_interpreter.setText("⏳ wait...")
            self.btn_refresh_interpreter.setFixedWidth(80)
            populate_interpreter_cmb_in_thread()

        def update_bottom_text():
            current = (self.cmb_interpreter.currentText() or "").strip()

            if not current:
                self.terminal_input.clear()
                return

            if current == "Searching Python":
                self.cmb_priority.setCurrentText("Normal")
                self.chk_save_output.setChecked(False)
                self.chk_run_in_background.setChecked(False)
                self.chk_run_external.setChecked(False)
                self.chk_run_current.setChecked(False)
                self.chk_show_advanced.setChecked(False)
                self.chk_detach_terminal.setChecked(False)
                self.chk_set_timeout.setChecked(False)
                self.chk_root_priv.setChecked(False)
                self.terminal_input.setPlainText(f"python3 {self.path}")
                return

            text = (self.terminal_input.toPlainText() or "")

            try:
                pattern = re.compile(
                    r'(?P<interp>\S*python(?:\d+)?\S*)(?P<flags>(?:\s+(?:-[^\s]+))*?)\s+' + re.escape(self.path),
                    flags=re.IGNORECASE
                )
            except Exception:
                pattern = None

            replaced = False
            if pattern:
                m = pattern.search(text)
                if m:
                    interp_start = m.start('interp')
                    interp_end_after_path = m.end()
                    flags = m.group('flags') or ""
                    new_fragment = f"{current}{flags} {self.path}"
                    new_text = text[:interp_start] + new_fragment + text[m.end():]
                    self.terminal_input.setPlainText(new_text)
                    replaced = True

            if not replaced:
                self.cmb_priority.setCurrentText("Normal")
                self.chk_save_output.setChecked(False)
                self.chk_run_in_background.setChecked(False)
                self.chk_run_external.setChecked(False)
                self.chk_run_current.setChecked(False)
                self.chk_show_advanced.setChecked(False)
                self.chk_detach_terminal.setChecked(False)
                self.chk_set_timeout.setChecked(False)
                self.chk_root_priv.setChecked(False)
                self.terminal_input.setPlainText(f"{current} {self.path}")

        populate_interpreter_cmb(self.controller.interpreters_json)
        self.btn_refresh_interpreter.clicked.connect(on_refresh_clicked)
        self.cmb_interpreter.currentIndexChanged.connect(update_bottom_text)
        self.cmb_interpreter.currentIndexChanged.connect(self.update_imports_info)

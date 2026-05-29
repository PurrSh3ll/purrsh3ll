import logging
import os
import re
import json
import base64
import shutil
import shlex

logger = logging.getLogger(__name__)
from PyQt6.QtCore import Qt, QEvent, QTimer, QSize, QObject
from PyQt6.QtGui import QAction, QKeySequence, QFont, QColor, QIcon, QCursor
from PyQt6.QtWidgets import (QApplication, QMenu, QToolButton, QPushButton, QWidget,
                              QHBoxLayout, QVBoxLayout, QLineEdit, QLabel, QDialog,
                              QComboBox, QInputDialog, QSplitter, QFileDialog, QMessageBox)
from QTermWidget import QTermWidget
from gui.widgets.terminal_wrapper import TerminalWrapper

_ANSI_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07')
_PROMPT_RE = re.compile(r'[$%#]\s*$')


class _TermRepaintFilter(QObject):
    """Debounced resize → full repaint to eliminate black bands after geometry changes."""
    def __init__(self, terminal):
        super().__init__(terminal)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(50)
        self._timer.timeout.connect(terminal.update)
        terminal.installEventFilter(self)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.Resize:
            self._timer.start()
        return False

class TerminalTabsMixin:
    def _on_terminal_received(self, data: str):
        data = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', data)
        data = re.sub(r'\x1b\][^\x07]*\x07', '', data)
        type(self).terminal_buffer += data

        pattern = re.compile(r'PurrSh3ll opened >>\s*(.*?)(?=\r?\n|$)', re.DOTALL)
        while True:
            m = pattern.search(type(self).terminal_buffer)
            if not m:
                break
            result = m.group(1).strip().split()
            filepath = result[0]
            mode = result[1] if len(result) == 2 else None
            if mode:
                self.open_new_tab_for_terminal(file=filepath, mode=mode)
            else:
                self.open_new_tab_for_terminal(file=filepath)
            type(self).terminal_buffer = type(self).terminal_buffer[m.end():]

    def _add_new_terminal_tab(self, name=None, command=None, workdir=None):
        type(self).terminal_idx += 1
        idx = type(self).terminal_idx

        term = QTermWidget(0)
        term.setScrollBarPosition(QTermWidget.ScrollBarPosition.ScrollBarRight)
        term.setStyleSheet(self.terminal_qss_scroll)
        term.setColorScheme(self.terminals_stylesheet)
        term.receivedData.connect(self._on_terminal_received)

        _log_state = {"cmd": None, "ts_start": 0, "output": [], "last_failed": None, "cwd": ""}
        _osc_re = re.compile(r'\x1b\]777;purrlog_(cmd|end);([^;\x07]+);(\d+)(?:;([^\x07]*))?\x07')
        _wrapper_ref = [None]

        def _on_log(data: str, _state=_log_state, _tid=f"terminal_{idx}"):
            if getattr(_wrapper_ref[0], "_agent_monitoring_paused", False):
                return
            for typ, payload, ts, cwd_b64 in _osc_re.findall(data):
                if typ == "cmd":
                    try:
                        cmd = base64.b64decode(payload + "==").decode("utf-8", errors="replace").strip()
                    except Exception:
                        cmd = payload
                    _state["cmd"] = cmd
                    _state["ts_start"] = int(ts)
                    _state["output"] = []
                    _state["cwd"] = ""
                    if cwd_b64:
                        try:
                            _state["cwd"] = base64.b64decode(cwd_b64 + "==").decode("utf-8", errors="replace").strip()
                        except Exception:
                            pass
                    # Hide overlay when new command starts
                    _w = _wrapper_ref[0]
                    if _w is not None:
                        _w.hide_error_overlay()
                elif typ == "end" and _state["cmd"] is not None:
                    exit_code = int(payload)
                    entry = {
                        "ts": _state["ts_start"],
                        "ts_end": int(ts),
                        "terminal": _tid,
                        "cmd": _state["cmd"],
                        "exit_code": exit_code,
                        "output": "".join(_state["output"]).strip()
                    }
                    _state["cmd"] = None
                    _state["output"] = []
                    if not getattr(self, "terminal_history_disabled", False):
                        log_path = os.path.join(self.base_path, "appdata", "logs", "terminal_history.jsonl")
                        os.makedirs(os.path.dirname(log_path), exist_ok=True)
                        try:
                            with open(log_path, "a", encoding="utf-8") as f:
                                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                            _max = getattr(self, "terminal_history_max_entries", 5000)
                            try:
                                with open(log_path, "r", encoding="utf-8") as f:
                                    lines = f.readlines()
                                if len(lines) > _max:
                                    with open(log_path, "w", encoding="utf-8") as f:
                                        f.writelines(lines[-_max:])
                            except Exception:
                                pass
                        except Exception:
                            logger.error("Failed to write terminal history to %s", log_path, exc_info=True)
                    # Show or hide error overlay
                    _w = _wrapper_ref[0]
                    if _w is not None:
                        if exit_code != 0:
                            _state["last_failed"] = {
                                "cmd":       entry["cmd"],
                                "exit_code": exit_code,
                                "output":    entry["output"],
                                "cwd":       _state.get("cwd", ""),
                            }
                            _w.show_error_overlay(exit_code)
                        else:
                            _w.hide_error_overlay()
            if _state["cmd"] is not None:
                clean = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', data)
                clean = re.sub(r'\x1b\][^\x07]*\x07', '', clean)
                if clean.strip():
                    _state["output"].append(clean)

        term.receivedData.connect(_on_log)

        try:
            base_font = QFont("Monospace", 11)
            try:
                term.setTerminalFont(base_font)
            except Exception:
                pass
        except Exception:
            pass

        try:
            term.setShellProgram("/bin/zsh")
            _fifo_dir = os.path.join(self.base_path, "appdata", "terminal_fifos")
            os.makedirs(_fifo_dir, exist_ok=True)
            _fifo_path = os.path.join(_fifo_dir, f"terminal_{idx}.fifo")
            if os.path.exists(_fifo_path):
                os.unlink(_fifo_path)
            os.mkfifo(_fifo_path)
            _fifo_fd = os.open(_fifo_path, os.O_RDWR | os.O_NONBLOCK)
            self.terminal_fifos[f"terminal_{idx}"] = (_fifo_path, _fifo_fd)
            _term_env_with_fifo = list(self._term_env) + [f"PURRSH_FIFO={_fifo_path}"]
            term.setEnvironment(_term_env_with_fifo)
            term.startShellProgram()
        except Exception:
            term.setEnvironment(self._term_env)
            try:
                term.startShellProgram()
            except Exception:
                pass

        term.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

        act_find = QAction("Find", self.widgets["terminal_groupbox"])

        def _apply_search_bar_style(t=term):
            fg = self.actual_theme.get('foreground', {})
            bg = self.actual_theme.get('background', {})
            text = fg.get('text', '#ffffff')
            bg_main = bg.get('main_window', '#2B2D30')
            bg_btn = bg.get('buttons', '#37373B')
            bg_hover = bg.get('buttons_hover', '#6C6C73')
            bg_input = bg.get('tab_bar', '#3B3E40')
            border = bg.get('buttons_pressed', '#2C5F8F')
            for child in t.findChildren(QWidget):
                if isinstance(child, QLineEdit):
                    child.setStyleSheet(
                        f"QLineEdit {{ background: {bg_input}; color: {text};"
                        f" border: 1px solid {border}; border-radius: 3px; padding: 2px 4px; }}"
                    )
                elif isinstance(child, (QToolButton, QPushButton)):
                    child.setStyleSheet(
                        f"QToolButton, QPushButton {{ background: {bg_btn}; color: {text};"
                        f" border: none; border-radius: 3px; padding: 2px 6px; }}"
                        f"QToolButton:hover, QPushButton:hover {{ background: {bg_hover}; }}"
                        f"QToolButton:pressed, QPushButton:pressed {{ background: {border}; }}"
                    )
                elif child is not t and not hasattr(child, 'sendText'):
                    child.setStyleSheet(f"background: {bg_main}; color: {text};")

        act_find.triggered.connect(lambda checked=False, t=term: (
            t.toggleShowSearchBar(),
            QTimer.singleShot(30, lambda: _apply_search_bar_style(t))
        ))

        def _on_context_menu(pos):
            menu = QMenu(self.widgets["terminal_groupbox"])
            menu.addAction(self._act_copy_selection)
            menu.addAction(self._act_paste_selection)
            menu.addSeparator()
            menu.addAction(self._act_paste_clipboard)
            menu.addSeparator()
            _act_zi = QAction("Zoom In", menu)
            _act_zi.triggered.connect(lambda checked=False, t=term: (t.setFocus(), t.zoom(1)) if hasattr(t, "zoom") else self._zoom_in())
            _act_zo = QAction("Zoom Out", menu)
            _act_zo.triggered.connect(lambda checked=False, t=term: (t.setFocus(), t.zoom(-1)) if hasattr(t, "zoom") else self._zoom_out())
            _act_zr = QAction("Zoom Reset", menu)
            _act_zr.triggered.connect(lambda checked=False, t=term: (t.setFocus(), t.resetZoom()) if hasattr(t, "resetZoom") else self._zoom_reset())
            menu.addAction(_act_zi)
            menu.addAction(_act_zo)
            menu.addAction(_act_zr)
            menu.addSeparator()
            menu.addAction(act_find)
            menu.addSeparator()
            _scheme_menu = QMenu("Color scheme", menu)
            try:
                _scheme_dir = "/usr/share/qtermwidget6/color-schemes"
                _schemes = sorted(
                    f[:-len(".colorscheme")]
                    for f in os.listdir(_scheme_dir)
                    if f.endswith(".colorscheme")
                )
                for _s in _schemes:
                    _act_s = QAction(_s, _scheme_menu)
                    _act_s.triggered.connect(
                        lambda checked=False, t=term, s=_s: t.setColorScheme(s)
                    )
                    _scheme_menu.addAction(_act_s)
            except Exception:
                pass
            menu.addMenu(_scheme_menu)
            menu.addSeparator()
            _w = _wrapper_ref[0]
            _is_split = getattr(_w, '_split_term', None) is not None
            if _is_split:
                _unsplit_act = menu.addAction("Unsplit terminal")
                _unsplit_act.triggered.connect(
                    lambda checked=False, w=_w: self._unsplit_terminal(w)
                )
            else:
                _act_h = menu.addAction("Split View Left-Right")
                _act_h.triggered.connect(
                    lambda checked=False, w=_w, t=term: self._split_terminal_in_tab(w, t, Qt.Orientation.Horizontal)
                )
                _act_v = menu.addAction("Split View Top-Bottom")
                _act_v.triggered.connect(
                    lambda checked=False, w=_w, t=term: self._split_terminal_in_tab(w, t, Qt.Orientation.Vertical)
                )
            menu.exec(term.mapToGlobal(pos))

        term.customContextMenuRequested.connect(_on_context_menu)

        wrapper_widget = TerminalWrapper(console_widget=term, min_h=0,
                                         pref_h=0, parent=self.widgets["terminal_tabs"])
        _wrapper_ref[0] = wrapper_widget

        def _inject_and_hide(text, _t=term, _w=wrapper_widget):
            try:
                _t.sendText(text)
            except Exception:
                pass
            _w.hide_error_overlay()

        def _analyze_and_inject(_t=term, _w=wrapper_widget, _state=_log_state):
            _w.hide_error_overlay()
            cwd = (_state.get("last_failed") or {}).get("cwd", "")
            cmd = f'psfix --analyze{(" --cwd " + shlex.quote(cwd)) if cwd else ""}\n'
            try:
                _t.sendText(cmd)
            except Exception:
                pass

        wrapper_widget.set_error_callbacks(
            explain_fn=lambda: _inject_and_hide("psfix --explain\n"),
            fix_fn=lambda:     _inject_and_hide("psfix\n"),
            analyze_fn=lambda: _analyze_and_inject(),
        )

        self.widgets["terminal_tabs"].addTab(wrapper_widget, f"{name}" if name else f"Console {idx}")
        if command is not None:
            _sent = [False]
            _handler = [None]
            _osc_end_re = re.compile(r'\x1b\]777;purrlog_end;')
            def _on_ready(data, _t=term, _cmd=command):
                if _sent[0]:
                    return
                if _osc_end_re.search(data):
                    _sent[0] = True
                    try:
                        _t.receivedData.disconnect(_handler[0])
                    except Exception:
                        pass
                    QTimer.singleShot(50, lambda t=_t, cmd=_cmd: t.sendText(cmd))
            _handler[0] = _on_ready
            term.receivedData.connect(_on_ready)

            def _fallback(sent=_sent, t=term, cmd=command, h=_handler):
                if not sent[0]:
                    sent[0] = True
                    try:
                        t.receivedData.disconnect(h[0])
                    except Exception:
                        pass
                    try:
                        t.sendText(cmd)
                    except Exception:
                        pass
            QTimer.singleShot(3000, _fallback)

        self.widgets["terminal_tabs"].setCurrentIndex(self.widgets["terminal_tabs"].count() - 1)
        self.wrapper_to_console[wrapper_widget] = term
        self.terminals[f"terminal_{idx}"] = term
        term._style_children_cache = None
        term._repaint_filter = _TermRepaintFilter(term)

        self.update_dropdown_terminals()
        self.update_dropdown_menu_terminals()

        if callable(getattr(self, 'refresh_terminal_paused_colors', None)):
            self.refresh_terminal_paused_colors()

    def _open_agent_ai_tab(self):
        _logs_path = os.path.join(self.base_path, "appdata", "logs")
        self._add_new_terminal_tab(**self.console_args)
        _tid = f"terminal_{type(self).terminal_idx}"
        _tabs = self.widgets.get("terminal_tabs")
        if _tabs:
            _tabs.setTabText(_tabs.count() - 1, "Agent AI")

        t = self.terminals.get(_tid)
        if not t:
            return

        _cmd = ""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, "r", encoding="utf-8") as _f:
                    _cmd = json.load(_f).get("llama", {}).get("logs_terminal_cmd", "")
        except Exception:
            pass

        _sent = [False]
        _handler = [None]
        _osc_end_re = re.compile(r'\x1b\]777;purrlog_end;')
        payload = f"cd {_logs_path}\nclear\n"
        if _cmd:
            payload += f"{_cmd}\n"
        def _on_ready(data):
            if _sent[0]:
                return
            if _osc_end_re.search(data):
                _sent[0] = True
                try:
                    t.receivedData.disconnect(_handler[0])
                except Exception:
                    pass
                QTimer.singleShot(50, lambda: t.sendText(payload))
        _handler[0] = _on_ready
        t.receivedData.connect(_on_ready)

    def _show_terminal_options_dialog(self):
        dlg = QDialog()
        dlg.setWindowTitle("Agent Configuration")
        try:
            dlg.setStyleSheet(self.__class__.dialog_stylesheet)
        except Exception:
            pass
        dlg_layout = QVBoxLayout(dlg)
        dlg_layout.setContentsMargins(10, 10, 10, 10)
        dlg_layout.setSpacing(6)

        _cfg = {}
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, "r", encoding="utf-8") as _f:
                    _cfg = json.load(_f).get("llama", {})
        except Exception:
            pass

        _logs_cmd_edit = QLineEdit(dlg)
        _logs_cmd_edit.setText(_cfg.get("logs_terminal_cmd", ""))
        _logs_cmd_edit.setReadOnly(True)
        _logs_cmd_btn = QPushButton("edit", dlg)
        form = QHBoxLayout()
        form.addWidget(_logs_cmd_edit)
        form.addWidget(_logs_cmd_btn)
        form_row = QHBoxLayout()
        form_row.addWidget(QLabel("command to execute:"))
        form_row.addLayout(form)
        dlg_layout.addLayout(form_row)

        _agent_modes_dir = os.path.join(self.base_path, "appdata", "agent_modes", "agent_md")
        _agent_roles = []
        try:
            if os.path.isdir(_agent_modes_dir):
                _agent_roles = sorted(os.listdir(_agent_modes_dir))
        except Exception:
            pass
        _agent_role_combo = QComboBox(dlg)
        _agent_role_combo.addItem("none")
        _agent_role_combo.addItems(_agent_roles)
        _saved_agent_role = _cfg.get("agent_role", "")
        if _saved_agent_role in _agent_roles:
            _agent_role_combo.setCurrentText(_saved_agent_role)
        _btn_add_role = QPushButton("+", dlg)
        _btn_add_role.setFixedWidth(24)
        _btn_add_role.setToolTip("Import agent role file")
        _btn_del_role = QPushButton("−", dlg)
        _btn_del_role.setFixedWidth(24)
        _btn_del_role.setToolTip("Delete selected agent role")
        agent_role_row = QHBoxLayout()
        agent_role_row.addWidget(QLabel("agent role:"))
        agent_role_row.addWidget(_agent_role_combo)
        agent_role_row.addWidget(_btn_add_role)
        agent_role_row.addWidget(_btn_del_role)
        dlg_layout.addLayout(agent_role_row)

        _skills_dir = os.path.join(self.base_path, "appdata", "agent_modes", "skills")
        _skills = []
        try:
            if os.path.isdir(_skills_dir):
                _skills = sorted(os.listdir(_skills_dir))
        except Exception:
            pass
        _skills_combo = QComboBox(dlg)
        _skills_combo.addItem("none")
        _skills_combo.addItems(_skills)
        _saved_skills = _cfg.get("skills_set", "")
        if _saved_skills in _skills:
            _skills_combo.setCurrentText(_saved_skills)
        _btn_add_skills = QPushButton("+", dlg)
        _btn_add_skills.setFixedWidth(24)
        _btn_add_skills.setToolTip("Import skills set folder")
        _btn_del_skills = QPushButton("−", dlg)
        _btn_del_skills.setFixedWidth(24)
        _btn_del_skills.setToolTip("Delete selected skills set")
        skills_row = QHBoxLayout()
        skills_row.addWidget(QLabel("skills set:"))
        skills_row.addWidget(_skills_combo)
        skills_row.addWidget(_btn_add_skills)
        skills_row.addWidget(_btn_del_skills)
        dlg_layout.addLayout(skills_row)

        def _save_combos():
            try:
                cfg = {}
                if os.path.exists(self.config_path):
                    with open(self.config_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f) or {}
                cfg.setdefault("llama", {})["agent_role"] = _agent_role_combo.currentText()
                cfg["llama"]["skills_set"] = _skills_combo.currentText()
                with open(self.config_path, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
            except Exception as ex:
                pass
            settings_agent_combo = self.widgets.get("settings_agent_role_combo")
            if settings_agent_combo:
                settings_agent_combo.setCurrentText(_agent_role_combo.currentText())
            settings_skills = self.widgets.get("settings_skills_combo")
            if settings_skills:
                settings_skills.setCurrentText(_skills_combo.currentText())
            self.apply_agent_files(_agent_role_combo.currentText(), _skills_combo.currentText())

        _agent_role_combo.currentIndexChanged.connect(_save_combos)
        _skills_combo.currentIndexChanged.connect(_save_combos)

        def _on_edit_logs_cmd():
            edit_dlg = QDialog(dlg)
            edit_dlg.setWindowTitle("Edit value")
            edit_layout = QVBoxLayout(edit_dlg)
            edit_layout.setContentsMargins(10, 10, 10, 10)
            edit_layout.setSpacing(6)
            edit_field = QLineEdit(edit_dlg)
            edit_field.setText(_logs_cmd_edit.text())
            edit_layout.addWidget(edit_field)
            ok_btn = QPushButton("ok", edit_dlg)
            edit_layout.addWidget(ok_btn, alignment=Qt.AlignmentFlag.AlignRight)

            def _confirm():
                val = edit_field.text()
                _logs_cmd_edit.setText(val)
                try:
                    cfg = {}
                    if os.path.exists(self.config_path):
                        with open(self.config_path, "r", encoding="utf-8") as f:
                            cfg = json.load(f) or {}
                    cfg.setdefault("llama", {})["logs_terminal_cmd"] = val
                    with open(self.config_path, "w", encoding="utf-8") as f:
                        json.dump(cfg, f, indent=2, ensure_ascii=False)
                except Exception as ex:
                    pass
                settings_edit = self.widgets.get("settings_logs_terminal_edit")
                if settings_edit:
                    settings_edit.setText(val)
                edit_dlg.accept()

            ok_btn.clicked.connect(_confirm)
            edit_dlg.exec()

        def _sync_settings_role_add(name):
            sc = self.widgets.get("settings_agent_role_combo")
            if sc and sc.findText(name) == -1:
                sc.addItem(name)
            if sc:
                sc.setCurrentText(name)

        def _sync_settings_role_remove(name):
            sc = self.widgets.get("settings_agent_role_combo")
            if sc:
                idx = sc.findText(name)
                if idx != -1:
                    sc.removeItem(idx)
                sc.setCurrentText("none")

        def _sync_settings_skills_add(name):
            sc = self.widgets.get("settings_skills_combo")
            if sc and sc.findText(name) == -1:
                sc.addItem(name)
            if sc:
                sc.setCurrentText(name)

        def _sync_settings_skills_remove(name):
            sc = self.widgets.get("settings_skills_combo")
            if sc:
                idx = sc.findText(name)
                if idx != -1:
                    sc.removeItem(idx)
                sc.setCurrentText("none")

        def _on_add_agent_role():
            src, _ = QFileDialog.getOpenFileName(dlg, "Select agent role file", "", "All files (*)")
            if not src:
                return
            os.makedirs(_agent_modes_dir, exist_ok=True)
            dest = os.path.join(_agent_modes_dir, os.path.basename(src))
            try:
                shutil.copy2(src, dest)
            except Exception:
                return
            name = os.path.basename(src)
            if _agent_role_combo.findText(name) == -1:
                _agent_role_combo.addItem(name)
            _agent_role_combo.setCurrentText(name)
            _sync_settings_role_add(name)

        def _on_add_skills_set():
            src = QFileDialog.getExistingDirectory(dlg, "Select skills set folder", "")
            if not src:
                return
            os.makedirs(_skills_dir, exist_ok=True)
            dest = os.path.join(_skills_dir, os.path.basename(src))
            try:
                shutil.copytree(src, dest, dirs_exist_ok=True)
            except Exception:
                return
            name = os.path.basename(src)
            if _skills_combo.findText(name) == -1:
                _skills_combo.addItem(name)
            _skills_combo.setCurrentText(name)
            _sync_settings_skills_add(name)

        def _on_del_agent_role():
            name = _agent_role_combo.currentText()
            if not name or name == "none":
                return
            confirm = QMessageBox(dlg)
            confirm.setWindowTitle("Confirm deletion")
            confirm.setText(f"Delete agent role <b>{name}</b>?<br>This will remove the file permanently.")
            confirm.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
            confirm.setDefaultButton(QMessageBox.StandardButton.Cancel)
            try:
                confirm.setStyleSheet(self.__class__.dialog_stylesheet)
            except Exception:
                pass
            if confirm.exec() != QMessageBox.StandardButton.Yes:
                return
            path = os.path.join(_agent_modes_dir, name)
            try:
                if os.path.isfile(path):
                    os.remove(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path)
            except Exception:
                return
            idx = _agent_role_combo.findText(name)
            if idx != -1:
                _agent_role_combo.removeItem(idx)
            _agent_role_combo.setCurrentText("none")
            _sync_settings_role_remove(name)

        def _on_del_skills_set():
            name = _skills_combo.currentText()
            if not name or name == "none":
                return
            confirm = QMessageBox(dlg)
            confirm.setWindowTitle("Confirm deletion")
            confirm.setText(f"Delete skills set <b>{name}</b>?<br>This will remove the folder permanently.")
            confirm.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
            confirm.setDefaultButton(QMessageBox.StandardButton.Cancel)
            try:
                confirm.setStyleSheet(self.__class__.dialog_stylesheet)
            except Exception:
                pass
            if confirm.exec() != QMessageBox.StandardButton.Yes:
                return
            path = os.path.join(_skills_dir, name)
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                elif os.path.isfile(path):
                    os.remove(path)
            except Exception:
                return
            idx = _skills_combo.findText(name)
            if idx != -1:
                _skills_combo.removeItem(idx)
            _skills_combo.setCurrentText("none")
            _sync_settings_skills_remove(name)

        _btn_add_role.clicked.connect(_on_add_agent_role)
        _btn_del_role.clicked.connect(_on_del_agent_role)
        _btn_add_skills.clicked.connect(_on_add_skills_set)
        _btn_del_skills.clicked.connect(_on_del_skills_set)
        _logs_cmd_btn.clicked.connect(_on_edit_logs_cmd)
        dlg.exec()

    def _close_terminal_tab(self, index: int):
        if len(self.terminals) == 1:
            self._add_new_terminal_tab()

        widget = self.widgets["terminal_tabs"].widget(index)
        if widget is None:
            self.widgets["terminal_tabs"].removeTab(index)
            return

        console = self.wrapper_to_console.pop(widget, None)
        if console is None:
            try:
                inner = widget.findChild(QTermWidget)
                console = self.wrapper_to_console.pop(inner, None)
            except Exception:
                console = None

        if console is not None:
            try:
                for key, val in list(self.terminals.items()):
                    if val is console:
                        del self.terminals[key]
                        _fifo_info = self.terminal_fifos.pop(key, None)
                        if _fifo_info:
                            _fifo_p, _fifo_f = _fifo_info
                            try:
                                os.close(_fifo_f)
                            except Exception:
                                pass
                            try:
                                os.unlink(_fifo_p)
                            except Exception:
                                pass
                        break
            except Exception:
                pass
            try:
                console.receivedData.disconnect()
            except Exception:
                pass
            try:
                if hasattr(console, "stop") and callable(console.stop):
                    console.stop()
                else:
                    console.clear()
            except Exception:
                pass

        split_term = getattr(widget, '_split_term', None)
        if split_term is not None:
            try:
                split_term.receivedData.disconnect()
            except Exception:
                pass
            splitter = getattr(widget, '_split_splitter', None)
            if splitter:
                try:
                    splitter.deleteLater()
                except Exception:
                    pass

        try:
            widget.deleteLater()
        except Exception:
            pass

        self.widgets["terminal_tabs"].removeTab(index)
        self.update_dropdown_terminals()
        self.update_dropdown_menu_terminals()

    def refresh_terminal_paused_colors(self):
        tabs = self.widgets.get("terminal_tabs")
        if tabs is None:
            return
        fg = self.actual_theme.get('foreground', {})
        paused_color = fg.get('term_paused_tab', '#FF4D4D')
        paused_sel_color = fg.get('term_paused_tab_selected', '#FF1A1A')
        normal_color = fg.get('tab_bar', '#ffffff')
        normal_sel_color = fg.get('tab_bar_selected', '#ffffff')
        current = tabs.currentIndex()
        bar = tabs.tabBar()
        for j in range(tabs.count()):
            w = tabs.widget(j)
            paused = getattr(w, '_agent_monitoring_paused', False)
            if paused:
                bar.setTabTextColor(j, QColor(paused_sel_color if j == current else paused_color))
            else:
                bar.setTabTextColor(j, QColor(normal_sel_color if j == current else normal_color))

    def _rename_terminal_tab(self, idx: int):
        try:
            tabs = self.widgets["terminal_tabs"]
            tabbar = tabs.tabBar()
            if idx < 0 or idx >= tabs.count():
                return
            dialog = QInputDialog(tabbar)
            dialog.setWindowTitle("Rename tab")
            dialog.setLabelText("New name:")
            dialog.setTextValue(tabs.tabText(idx))
            dialog.setInputMode(QInputDialog.InputMode.TextInput)
            try:
                qss = getattr(type(self), "qss_QInputDialog_terminal", None)
                if qss:
                    dialog.setStyleSheet(qss)
            except Exception:
                pass
            if dialog.exec():
                new_name = dialog.textValue()
                if new_name and new_name.strip():
                    tabs.setTabText(idx, new_name.strip())
                    try:
                        self.update_dropdown_terminals()
                        self.update_dropdown_menu_terminals()
                    except Exception:
                        pass
        except Exception as e:
            pass

    def _on_tab_bar_context_menu(self, pos):
        try:
            tabs = self.widgets["terminal_tabs"]
            tabbar = tabs.tabBar()
            idx = tabbar.tabAt(tabbar.mapFromGlobal(QCursor.pos()))
            if idx < 0:
                idx = tabs.currentIndex()

            menu = QMenu(tabbar)
            rename_action = QAction("Rename", menu)
            close_action = QAction("Close tab", menu)
            close_others_action = QAction("Close Others", menu)
            close_all_action = QAction("Close All", menu)

            tab_widget = tabs.widget(idx)
            _paused = getattr(tab_widget, "_agent_monitoring_paused", False)
            monitor_action = QAction(
                "Resume Agent Monitoring" if _paused else "Pause Agent Monitoring", menu
            )

            menu.addAction(rename_action)
            menu.addAction(close_action)
            menu.addSeparator()
            menu.addAction(close_others_action)
            menu.addAction(close_all_action)
            menu.addSeparator()
            menu.addAction(monitor_action)

            def rename_handler(checked=False, i=idx):
                try:
                    dialog = QInputDialog(tabbar)
                    dialog.setWindowTitle("Rename tab")
                    dialog.setLabelText("New name:")
                    dialog.setTextValue(tabs.tabText(i))
                    dialog.setInputMode(QInputDialog.InputMode.TextInput)
                    try:
                        qss = getattr(type(self), "qss_QInputDialog_terminal", None)
                        if qss:
                            dialog.setStyleSheet(qss)
                    except Exception:
                        pass
                    if dialog.exec():
                        new_name = dialog.textValue().strip()
                        if new_name:
                            w = tabs.widget(i)
                            paused = getattr(w, "_agent_monitoring_paused", False)
                            clean = new_name[2:] if new_name.startswith("⊘ ") else new_name
                            tabs.setTabText(i, "⊘ " + clean if paused else clean)
                            try:
                                self.update_dropdown_terminals()
                                self.update_dropdown_menu_terminals()
                            except Exception:
                                pass
                except Exception as e:
                    pass

            def close_handler(checked=False, i=idx):
                try:
                    tabs.tabCloseRequested.emit(i)
                except Exception as e:
                    pass

            def close_others_handler(checked=False, i=idx):
                try:
                    for j in sorted([j for j in range(tabs.count()) if j != i], reverse=True):
                        tabs.tabCloseRequested.emit(j)
                except Exception as e:
                    pass

            def close_all_handler(checked=False, i=idx):
                try:
                    for j in sorted(range(tabs.count()), reverse=True):
                        tabs.tabCloseRequested.emit(j)
                except Exception as e:
                    pass

            def monitor_handler(checked=False, i=idx):
                try:
                    w = tabs.widget(i)
                    if w is None:
                        return
                    w._agent_monitoring_paused = not getattr(w, "_agent_monitoring_paused", False)
                    name = tabs.tabText(i)
                    if w._agent_monitoring_paused:
                        if not name.startswith("⊘ "):
                            tabs.setTabText(i, "⊘ " + name)
                    else:
                        if name.startswith("⊘ "):
                            tabs.setTabText(i, name[2:])
                    self.refresh_terminal_paused_colors()
                    self.update_dropdown_terminals()
                    self.update_dropdown_menu_terminals()
                except Exception as e:
                    pass

            rename_action.triggered.connect(rename_handler)
            close_action.triggered.connect(close_handler)
            close_others_action.triggered.connect(close_others_handler)
            close_all_action.triggered.connect(close_all_handler)
            monitor_action.triggered.connect(monitor_handler)
            menu.exec(QCursor.pos())

        except Exception as e:
            pass

    def _split_terminal_in_tab(self, wrapper_widget, term, orientation=Qt.Orientation.Horizontal):
        if getattr(wrapper_widget, '_split_term', None) is not None:
            self._unsplit_terminal(wrapper_widget)
            return

        layout = wrapper_widget.layout()
        layout.removeWidget(term)

        splitter = QSplitter(orientation, wrapper_widget)
        new_term = self._create_split_terminal(wrapper_widget)
        splitter.addWidget(term)
        splitter.addWidget(new_term)
        splitter.setSizes([500, 500])
        layout.addWidget(splitter)

        wrapper_widget._split_term = new_term
        wrapper_widget._split_splitter = splitter

    def _unsplit_terminal(self, wrapper_widget):
        split_term = getattr(wrapper_widget, '_split_term', None)
        splitter = getattr(wrapper_widget, '_split_splitter', None)
        if split_term is None:
            return

        term = self.wrapper_to_console.get(wrapper_widget)
        layout = wrapper_widget.layout()

        if term:
            layout.addWidget(term)

        try:
            split_term.receivedData.disconnect()
        except Exception:
            pass
        if splitter:
            splitter.deleteLater()

        wrapper_widget._split_term = None
        wrapper_widget._split_splitter = None

    def _create_split_terminal(self, wrapper_widget):
        term = QTermWidget(0)
        term.setScrollBarPosition(QTermWidget.ScrollBarPosition.ScrollBarRight)
        term.setStyleSheet(self.terminal_qss_scroll)
        term.setColorScheme(self.terminals_stylesheet)
        try:
            term.setShellProgram("/bin/zsh")
            term.setEnvironment(self._term_env)
            term.startShellProgram()
        except Exception:
            pass
        try:
            term.setTerminalFont(QFont("Monospace", 11))
        except Exception:
            pass

        term.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

        def _on_ctx(pos, t=term, w=wrapper_widget):
            menu = QMenu(self.widgets["terminal_groupbox"])
            menu.addAction("Copy selection", lambda: (hasattr(t, "copySelection") and t.copySelection()) or (hasattr(t, "copyClipboard") and t.copyClipboard()))
            menu.addAction("Paste selection", lambda: (hasattr(t, "pasteSelection") and t.pasteSelection()) or (hasattr(t, "pasteClipboard") and t.pasteClipboard()))
            menu.addSeparator()
            menu.addAction("Paste clipboard", lambda: hasattr(t, "pasteClipboard") and t.pasteClipboard())
            menu.addSeparator()
            act_zi = QAction("Zoom In", menu)
            act_zi.triggered.connect(lambda checked=False, tt=t: (tt.setFocus(), QTimer.singleShot(0, self._zoom_in)))
            act_zo = QAction("Zoom Out", menu)
            act_zo.triggered.connect(lambda checked=False, tt=t: (tt.setFocus(), QTimer.singleShot(0, self._zoom_out)))
            act_zr = QAction("Zoom Reset", menu)
            act_zr.triggered.connect(lambda checked=False, tt=t: (tt.setFocus(), QTimer.singleShot(0, self._zoom_reset)))
            menu.addAction(act_zi)
            menu.addAction(act_zo)
            menu.addAction(act_zr)
            menu.addSeparator()
            _scheme_menu = QMenu("Color scheme", menu)
            try:
                _scheme_dir = "/usr/share/qtermwidget6/color-schemes"
                _schemes = sorted(
                    f[:-len(".colorscheme")]
                    for f in os.listdir(_scheme_dir)
                    if f.endswith(".colorscheme")
                )
                for _s in _schemes:
                    _act_s = QAction(_s, _scheme_menu)
                    _act_s.triggered.connect(
                        lambda checked=False, tt=t, s=_s: tt.setColorScheme(s)
                    )
                    _scheme_menu.addAction(_act_s)
            except Exception:
                pass
            menu.addMenu(_scheme_menu)
            menu.addSeparator()
            act_unsplit = QAction("Unsplit terminal", menu)
            act_unsplit.triggered.connect(lambda checked=False, ww=w: self._unsplit_terminal(ww))
            menu.addAction(act_unsplit)
            menu.exec(t.mapToGlobal(pos))

        term.customContextMenuRequested.connect(_on_ctx)

        class _SplitWheelFilter(QObject):
            def eventFilter(self_, watched, event):
                if event.type() == QEvent.Type.Wheel:
                    if QApplication.keyboardModifiers() & Qt.KeyboardModifier.ControlModifier:
                        if watched is term or term.isAncestorOf(watched):
                            delta = event.angleDelta().y()
                            try:
                                if delta > 0 and hasattr(term, "zoom"):
                                    term.zoom(1)
                                elif delta < 0 and hasattr(term, "zoom"):
                                    term.zoom(-1)
                            except Exception:
                                pass
                            return True
                return False

        term._split_wheel_filter = _SplitWheelFilter(term)
        app_instance = QApplication.instance()
        if app_instance is not None:
            app_instance.installEventFilter(term._split_wheel_filter)

        return term

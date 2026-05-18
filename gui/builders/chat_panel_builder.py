from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QSizePolicy,
    QComboBox, QDialog, QPlainTextEdit, QFrame, QToolButton, QMenu, QLineEdit,
    QFormLayout,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QMovie, QAction, QTextOption
from QTermWidget import QTermWidget
import re

import os
import json

from core.controller import controller_instance
from gui.widgets.custom_frame import CustomFrame
from gui.widgets.web_preview import WebPreview

c = controller_instance

_PRESETS_PATH = None  # set on first use


def _presets_path():
    global _PRESETS_PATH
    if _PRESETS_PATH is None:
        _PRESETS_PATH = os.path.join(c.base_path, "appdata", "chat_presets.json")
    return _PRESETS_PATH


def _load_presets():
    p = _presets_path()
    if not os.path.exists(p):
        return []
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f).get("presets", [])
    except Exception:
        return []


def _save_presets(presets):
    p = _presets_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    try:
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"presets": presets}, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def build_chat_panel(main_window):

    chat_panel = CustomFrame(c.widgets["central_widget"])
    chat_panel.resize(chat_panel.start_width, c.widgets["main_window"].height())
    chat_panel.move(c.widgets["main_window"].width() - chat_panel.start_width, 0)
    chat_panel.hide()

    chat_panel_layout = QVBoxLayout()
    chat_panel_layout.setContentsMargins(0, 0, 0, 0)
    chat_panel_layout.setSpacing(0)
    chat_panel.setLayout(chat_panel_layout)

    center_container = QWidget()
    center_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    center_layout = QVBoxLayout(center_container)
    center_layout.setContentsMargins(6, 6, 6, 0)
    center_layout.setSpacing(0)

    future_label = QLabel()
    future_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    _chat_movie = QMovie(os.path.join(c.base_path, "icons", "uncensored_chat.gif"))
    future_label.setMovie(_chat_movie)
    _chat_movie.start()
    center_layout.addWidget(future_label, alignment=Qt.AlignmentFlag.AlignCenter)

    # Terminal lives inside center_container so it shares the same layout slot
    _term_container = QWidget()
    _term_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    _term_layout = QVBoxLayout(_term_container)
    _term_layout.setContentsMargins(0, 0, 0, 0)
    _term_container.hide()
    center_layout.addWidget(_term_container)

    chat_panel_layout.addWidget(center_container)

    # Footer: cmd_preview + bottom_row in one Fixed-height container
    footer_widget = QWidget()
    footer_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    footer_layout = QVBoxLayout(footer_widget)
    footer_layout.setContentsMargins(0, 0, 0, 0)
    footer_layout.setSpacing(0)

    # Command preview
    cmd_preview_edit = QPlainTextEdit()
    cmd_preview_edit.setObjectName("script_term")
    cmd_preview_edit.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
    cmd_preview_edit.setFixedHeight(104)
    cmd_preview_widget = QWidget()
    cmd_preview_widget_layout = QHBoxLayout(cmd_preview_widget)
    cmd_preview_widget_layout.setContentsMargins(6, 4, 6, 0)
    cmd_preview_widget_layout.addWidget(cmd_preview_edit)
    footer_layout.addWidget(cmd_preview_widget)

    # Bottom row
    bottom_row = QHBoxLayout()
    bottom_row.setSpacing(5)
    bottom_row.setContentsMargins(6, 4, 6, 6)

    chat_combo_interface = QComboBox()
    chat_combo_interface.addItems(["cli", "web"])

    chat_combo_custom = QComboBox()

    btn_height = 28

    chat_btn_add = QPushButton("⚙")
    chat_btn_add.setMinimumHeight(btn_height)

    chat_btn_info = QPushButton("ℹ")
    chat_btn_info.setMinimumHeight(btn_height)

    chat_btn_run = QToolButton()
    chat_btn_run.setMinimumHeight(btn_height)
    chat_btn_run.setText("run")
    chat_btn_run.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
    _run_mode_menu = QMenu()
    _action_run = QAction("run", chat_btn_run)
    _action_connect = QAction("connect", chat_btn_run)
    _run_mode_menu.addAction(_action_run)
    _run_mode_menu.addAction(_action_connect)
    chat_btn_run.setMenu(_run_mode_menu)
    def _on_mode_selected(action):
        chat_btn_run.setText(action.text())
        is_connect = action.text() == "connect"
        chat_combo_custom.setVisible(not is_connect)
        chat_btn_add.setVisible(not is_connect)
        chat_btn_info.setVisible(not is_connect)
        cmd_preview_widget.setVisible(not is_connect)
        if not is_connect:
            _refresh_custom_combo()

    _run_mode_menu.triggered.connect(_on_mode_selected)

    for widget in (chat_combo_interface, chat_combo_custom, chat_btn_add, chat_btn_info, chat_btn_run):
        widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        bottom_row.addWidget(widget)

    footer_layout.addLayout(bottom_row)
    chat_panel_layout.addWidget(footer_widget)

    # ── Run / stop logic (CLI + Web) ──────────────────────────────────────────

    _running = [False]
    _chat_term = [None]
    _chat_webview = [None]
    _connect_tmpdir = [None]
    _prev_btn_text = ["run"]
    _osc_end_re = re.compile(r'\x1b\]777;purrlog_end;')
    _STOP_STYLE = (
        "QToolButton { background-color: #8B2222; color: #ffffff; }"
        "QToolButton:hover { background-color: #A52A2A; }"
        "QToolButton:pressed { background-color: #6B1111; }"
    )
    _controls = [chat_combo_interface, chat_combo_custom, chat_btn_add, chat_btn_info]

    def _enter_running_state():
        _prev_btn_text[0] = chat_btn_run.text()
        future_label.hide()
        cmd_preview_widget.hide()
        _term_container.show()
        for w in _controls:
            w.setEnabled(False)
        chat_btn_run.setText("stop")
        chat_btn_run.setMenu(None)
        chat_btn_run.setPopupMode(QToolButton.ToolButtonPopupMode.DelayedPopup)
        chat_btn_run.setStyleSheet(_STOP_STYLE)
        _running[0] = True

    def _leave_running_state():
        _term_container.hide()
        future_label.show()
        if _prev_btn_text[0] != "connect":
            cmd_preview_widget.show()
        for w in _controls:
            w.setEnabled(True)
        chat_btn_run.setText(_prev_btn_text[0])
        chat_btn_run.setMenu(_run_mode_menu)
        chat_btn_run.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        chat_btn_run.setStyleSheet(getattr(c.__class__, "button_stylesheet", ""))
        _running[0] = False

    def _start_cli_session(command, extra_env=None):
        term = QTermWidget(0)
        term.setScrollBarPosition(QTermWidget.ScrollBarPosition.ScrollBarRight)
        try:
            term.setStyleSheet(c.__class__.terminal_qss_scroll)
            term.setColorScheme(c.__class__.terminals_stylesheet)
        except Exception:
            pass
        try:
            from PyQt6.QtGui import QFont
            term.setTerminalFont(QFont("Monospace", 11))
        except Exception:
            pass
        try:
            term.setShellProgram("/bin/zsh")
            env = list(c._term_env) + (extra_env or [])
            term.setEnvironment(env)
            term.startShellProgram()
        except Exception:
            pass

        _term_layout.addWidget(term)
        _chat_term[0] = term
        _enter_running_state()

        _sent = [False]
        _handler = [None]

        def _on_ready(data):
            if _sent[0]:
                return
            if _osc_end_re.search(data):
                _sent[0] = True
                try:
                    term.receivedData.disconnect(_handler[0])
                except Exception:
                    pass
                QTimer.singleShot(50, lambda t=term, cmd=command: t.sendText(cmd + "\n"))

        _handler[0] = _on_ready
        term.receivedData.connect(_on_ready)

        def _fallback(sent=_sent, handler=_handler, t=term, cmd=command):
            if not sent[0]:
                sent[0] = True
                try:
                    t.receivedData.disconnect(handler[0])
                except Exception:
                    pass
                try:
                    t.sendText(cmd + "\n")
                except Exception:
                    pass

        QTimer.singleShot(3000, _fallback)

    def _start_web_session():
        dlg = QDialog(chat_panel)
        dlg.setWindowTitle("Open URL")
        dlg.setMinimumWidth(360)
        dlg.setStyleSheet(getattr(c, "chat_panel_dialog_stylesheet", ""))
        dlg_layout = QVBoxLayout(dlg)
        dlg_layout.setContentsMargins(16, 16, 16, 12)
        dlg_layout.setSpacing(10)

        header = QLabel("Enter URL", dlg)
        header.setStyleSheet("font-weight: bold; font-size: 12px;")
        dlg_layout.addWidget(header)

        url_edit = QLineEdit(dlg)
        url_edit.setPlaceholderText("https://example.com")
        url_edit.setText("http://localhost:8000")
        url_edit.selectAll()
        dlg_layout.addWidget(url_edit)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn_cancel = QPushButton("Cancel", dlg)
        btn_cancel.setFixedWidth(80)
        btn_ok = QPushButton("Open", dlg)
        btn_ok.setFixedWidth(80)
        btn_row.addWidget(btn_cancel)
        btn_row.addWidget(btn_ok)
        dlg_layout.addLayout(btn_row)

        btn_cancel.clicked.connect(dlg.reject)
        btn_ok.clicked.connect(dlg.accept)
        url_edit.returnPressed.connect(dlg.accept)

        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        raw = url_edit.text().strip()
        if not raw:
            return
        if not raw.startswith(("http://", "https://", "file://")):
            raw = "https://" + raw

        # Capture the command before UI state changes
        _web_launch_cmd = cmd_preview_edit.toPlainText().strip()

        from PyQt6.QtCore import QUrl
        webview = WebPreview(parent=_term_container)
        webview.load(QUrl(raw))
        _term_layout.addWidget(webview)
        _chat_webview[0] = webview
        _enter_running_state()
        chat_btn_info.setEnabled(True)

        # Populate info dialog with a terminal running the launch command
        _launch_info_terminal(_web_launch_cmd)

    def _launch_info_terminal(command):
        chat_info_dialog.setMinimumSize(520, 380)
        server_log_label.hide()
        _info_term_container.show()

        term = QTermWidget(0)
        term.setScrollBarPosition(QTermWidget.ScrollBarPosition.ScrollBarRight)
        try:
            term.setStyleSheet(c.__class__.terminal_qss_scroll)
            term.setColorScheme(c.__class__.terminals_stylesheet)
        except Exception:
            pass
        try:
            from PyQt6.QtGui import QFont
            term.setTerminalFont(QFont("Monospace", 11))
        except Exception:
            pass
        try:
            term.setShellProgram("/bin/zsh")
            term.setEnvironment(c._term_env)
            term.startShellProgram()
        except Exception:
            pass

        _info_term_layout.addWidget(term)
        _info_term[0] = term

        if not command:
            return

        _sent = [False]
        _handler = [None]

        def _on_ready(data):
            if _sent[0]:
                return
            if _osc_end_re.search(data):
                _sent[0] = True
                try:
                    term.receivedData.disconnect(_handler[0])
                except Exception:
                    pass
                QTimer.singleShot(50, lambda t=term, cmd=command: t.sendText(cmd + "\n"))

        _handler[0] = _on_ready
        term.receivedData.connect(_on_ready)

        def _fallback(sent=_sent, handler=_handler, t=term, cmd=command):
            if not sent[0]:
                sent[0] = True
                try:
                    t.receivedData.disconnect(handler[0])
                except Exception:
                    pass
                try:
                    t.sendText(cmd + "\n")
                except Exception:
                    pass

        QTimer.singleShot(3000, _fallback)

    def _stop_session():
        term = _chat_term[0]
        if term is not None:
            try:
                term.receivedData.disconnect()
            except Exception:
                pass
            try:
                if hasattr(term, "stop"):
                    term.stop()
            except Exception:
                pass
            try:
                _term_layout.removeWidget(term)
                term.setParent(None)
                term.deleteLater()
            except Exception:
                pass
            _chat_term[0] = None

        webview = _chat_webview[0]
        if webview is not None:
            try:
                webview.stop()
                _term_layout.removeWidget(webview)
                webview.setParent(None)
                webview.deleteLater()
            except Exception:
                pass
            _chat_webview[0] = None

        info_term = _info_term[0]
        if info_term is not None:
            try:
                info_term.receivedData.disconnect()
            except Exception:
                pass
            try:
                if hasattr(info_term, "stop"):
                    info_term.stop()
            except Exception:
                pass
            try:
                _info_term_layout.removeWidget(info_term)
                info_term.setParent(None)
                info_term.deleteLater()
            except Exception:
                pass
            _info_term[0] = None
            _info_term_container.hide()
            server_log_label.show()
            chat_info_dialog.setMinimumSize(0, 0)

        if _connect_tmpdir[0] is not None:
            import shutil
            try:
                shutil.rmtree(_connect_tmpdir[0], ignore_errors=True)
            except Exception:
                pass
            _connect_tmpdir[0] = None

        _leave_running_state()

    def _start_connect_session():
        dlg = QDialog(chat_panel)
        dlg.setWindowTitle("Connect to API")
        dlg.setMinimumWidth(380)
        dlg.setStyleSheet(getattr(c, "chat_panel_dialog_stylesheet", ""))
        dlg_layout = QVBoxLayout(dlg)
        dlg_layout.setContentsMargins(16, 16, 16, 12)
        dlg_layout.setSpacing(10)

        header = QLabel("OpenAI Compatible API", dlg)
        header.setStyleSheet("font-weight: bold; font-size: 12px;")
        dlg_layout.addWidget(header)

        info = QLabel("Connect to any server exposing an OpenAI-compatible endpoint\n"
                      "(llama.cpp, Ollama, vLLM, LM Studio, …)", dlg)
        info.setWordWrap(True)
        dlg_layout.addWidget(info)

        sep = QFrame(dlg)
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        dlg_layout.addWidget(sep)

        form = QFormLayout()
        form.setSpacing(8)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        base_edit = QLineEdit(dlg)
        base_edit.setText("http://localhost:11434/v1")
        base_edit.setPlaceholderText("http://IP:PORT/v1")
        form.addRow("API Base URL:", base_edit)

        model_edit = QLineEdit(dlg)
        model_edit.setPlaceholderText("e.g. llama3.2:1b, mistral")
        form.addRow("Model:", model_edit)

        key_edit = QLineEdit(dlg)
        key_edit.setText("none")
        key_edit.setPlaceholderText("API key (or 'none')")
        form.addRow("API Key:", key_edit)

        dlg_layout.addLayout(form)
        dlg_layout.addStretch(1)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn_cancel = QPushButton("Cancel", dlg)
        btn_cancel.setFixedWidth(80)
        btn_ok = QPushButton("Connect", dlg)
        btn_ok.setFixedWidth(80)
        btn_row.addWidget(btn_cancel)
        btn_row.addWidget(btn_ok)
        dlg_layout.addLayout(btn_row)

        btn_ok.setDefault(True)
        btn_cancel.setAutoDefault(False)
        btn_cancel.clicked.connect(dlg.reject)
        btn_ok.clicked.connect(dlg.accept)
        base_edit.returnPressed.connect(dlg.accept)
        model_edit.returnPressed.connect(dlg.accept)
        key_edit.returnPressed.connect(dlg.accept)

        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        api_base = base_edit.text().strip() or "http://localhost:11434/v1"
        model = model_edit.text().strip() or "model"
        api_key = key_edit.text().strip() or "none"

        import tempfile
        tmpdir = tempfile.mkdtemp(prefix="purrsh_aichat_")
        _connect_tmpdir[0] = tmpdir

        config_yaml = (
            f"model: purrsh:{model}\n\n"
            f"clients:\n"
            f"  - type: openai-compatible\n"
            f"    name: purrsh\n"
            f"    api_base: {api_base}\n"
            f"    api_key: {api_key}\n"
            f"    models:\n"
            f"      - name: {model}\n"
        )
        with open(os.path.join(tmpdir, "config.yaml"), "w", encoding="utf-8") as f:
            f.write(config_yaml)

        aichat_path = ""
        try:
            if os.path.exists(c.config_path):
                with open(c.config_path, "r", encoding="utf-8") as _f:
                    aichat_path = json.load(_f).get("llama", {}).get("llm_cli_path", "")
        except Exception:
            pass
        if not aichat_path:
            aichat_path = "aichat"

        extra_env = [f"AICHAT_CONFIG_DIR={tmpdir}"]
        command = f"{aichat_path} -s connect"
        _start_cli_session(command, extra_env=extra_env)

    def _on_run_clicked():
        if _running[0]:
            _stop_session()
        elif chat_combo_interface.currentText() == "cli":
            if chat_btn_run.text() == "connect":
                _start_connect_session()
            else:
                command = cmd_preview_edit.toPlainText().strip()
                if command:
                    _start_cli_session(command)
        elif chat_combo_interface.currentText() == "web":
            _start_web_session()

    chat_btn_run.clicked.connect(_on_run_clicked)

    # ── Preset / model logic ───────────────────────────────────────────────────

    _WEB_DOCKER_CMD = (
        "sudo docker rm -f open-webui; "
        "sudo docker run -d --network=host "
        "-e OLLAMA_BASE_URL=http://localhost:11434 "
        "-e PORT=3000 "
        "-v open-webui:/app/backend/data "
        "--name open-webui "
        "ghcr.io/open-webui/open-webui:main"
    )

    def _load_ollama_models():
        """Return list of model names from globally defined profiles with provider=ollama."""
        try:
            with open(c.config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            profiles = cfg.get("api_providers", {}).get("profiles", [])
            return [p["model"] for p in profiles
                    if p.get("provider", "").lower() == "ollama" and p.get("model")]
        except Exception:
            return []

    def _is_run_mode():
        return chat_btn_run.text() == "run"

    def _refresh_custom_combo():
        category = chat_combo_interface.currentText()
        chat_combo_custom.blockSignals(True)
        chat_combo_custom.clear()

        if _is_run_mode():
            # Load ollama models from global profiles
            models = _load_ollama_models()
            for m in models:
                chat_combo_custom.addItem(m)
            if not models:
                chat_combo_custom.addItem("(no ollama models)")
            # Set command preview immediately for first item
            chat_combo_custom.blockSignals(False)
            _on_custom_changed()
        else:
            # Legacy preset behaviour
            presets = _load_presets()
            chat_combo_custom.addItem("custom")
            for p in presets:
                if p.get("category") == category:
                    chat_combo_custom.addItem(p.get("name", ""))
            chat_combo_custom.blockSignals(False)
            cmd_preview_edit.setPlainText("")

    def _on_custom_changed():
        if not _is_run_mode():
            # Legacy preset behaviour
            name = chat_combo_custom.currentText()
            if name == "custom":
                cmd_preview_edit.setPlainText("")
                return
            category = chat_combo_interface.currentText()
            presets = _load_presets()
            for p in presets:
                if p.get("category") == category and p.get("name") == name:
                    cmd_preview_edit.setPlainText(p.get("command", ""))
                    return
            cmd_preview_edit.setPlainText("")
            return

        # Run mode: generate command from selected ollama model
        model = chat_combo_custom.currentText()
        if not model or model == "(no ollama models)":
            cmd_preview_edit.setPlainText("")
            return
        category = chat_combo_interface.currentText()
        if category == "cli":
            cmd_preview_edit.setPlainText(f"ollama run {model}")
        else:
            cmd_preview_edit.setPlainText(_WEB_DOCKER_CMD)

    def _open_add_dialog():
        dlg = QDialog(chat_panel)
        dlg.setWindowTitle("Add preset")
        dlg.setMinimumWidth(360)
        dlg.setStyleSheet(getattr(c, "chat_panel_dialog_stylesheet", ""))
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(16, 16, 16, 12)
        layout.setSpacing(12)

        header = QLabel("New command preset", dlg)
        header.setStyleSheet("font-weight: bold; font-size: 12px;")
        layout.addWidget(header)

        sep = QFrame(dlg)
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(sep)

        form = QFormLayout()
        form.setSpacing(8)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        cat_combo = QComboBox(dlg)
        cat_combo.addItems(["cli", "web"])
        cat_combo.setCurrentText(chat_combo_interface.currentText())
        form.addRow("Category:", cat_combo)

        name_edit = QLineEdit(dlg)
        name_edit.setPlaceholderText("Preset name")
        form.addRow("Name:", name_edit)

        cmd_edit = QLineEdit(dlg)
        cmd_edit.setPlaceholderText("Command to execute")
        form.addRow("Command:", cmd_edit)

        layout.addLayout(form)
        layout.addStretch(1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        btn_row.addStretch(1)
        btn_cancel = QPushButton("Cancel", dlg)
        btn_cancel.setFixedWidth(80)
        btn_ok = QPushButton("Add", dlg)
        btn_ok.setFixedWidth(80)
        btn_row.addWidget(btn_cancel)
        btn_row.addWidget(btn_ok)
        layout.addLayout(btn_row)

        btn_cancel.clicked.connect(dlg.reject)

        def _confirm():
            name = name_edit.text().strip()
            cmd = cmd_edit.text().strip()
            cat = cat_combo.currentText()
            if not name or not cmd:
                return
            presets = _load_presets()
            presets.append({"name": name, "category": cat, "command": cmd})
            _save_presets(presets)
            _refresh_custom_combo()
            if cat == chat_combo_interface.currentText():
                chat_combo_custom.setCurrentText(name)
            dlg.accept()

        btn_ok.clicked.connect(_confirm)
        dlg.exec()

    def _open_manage_dialog():
        dlg = QDialog(chat_panel)
        dlg.setWindowTitle("Manage presets")
        dlg.setMinimumWidth(420)
        dlg.resize(440, 340)
        dlg.setStyleSheet(getattr(c, "chat_panel_dialog_stylesheet", ""))
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(16, 16, 16, 12)
        layout.setSpacing(10)

        header = QLabel("Saved command presets", dlg)
        header.setStyleSheet("font-weight: bold; font-size: 12px;")
        layout.addWidget(header)

        sep = QFrame(dlg)
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(sep)

        scroll_widget = QWidget(dlg)
        scroll_layout = QVBoxLayout(scroll_widget)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        scroll_layout.setSpacing(2)

        from PyQt6.QtWidgets import QScrollArea
        scroll = QScrollArea(dlg)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)

        def _build_list():
            while scroll_layout.count():
                item = scroll_layout.takeAt(0)
                w = item.widget()
                if w:
                    w.deleteLater()

            current_presets = _load_presets()
            if not current_presets:
                lbl = QLabel("No presets saved.", scroll_widget)
                lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
                lbl.setStyleSheet("padding: 16px;")
                scroll_layout.addWidget(lbl)
                return

            by_cat = {}
            for p in current_presets:
                by_cat.setdefault(p.get("category", ""), []).append(p)

            for cat in sorted(by_cat.keys()):
                cat_lbl = QLabel(cat.upper(), scroll_widget)
                cat_lbl.setObjectName("manage_cat")
                scroll_layout.addWidget(cat_lbl)

                for p in by_cat[cat]:
                    row_w = QWidget(scroll_widget)
                    row_w.setObjectName("manage_row")
                    row_h = QHBoxLayout(row_w)
                    row_h.setContentsMargins(6, 4, 6, 4)
                    row_h.setSpacing(8)
                    name_lbl = QLabel(p.get("name", ""), row_w)
                    name_lbl.setObjectName("manage_name")
                    name_lbl.setFixedWidth(110)
                    cmd_lbl = QLabel(p.get("command", ""), row_w)
                    cmd_lbl.setObjectName("manage_cmd")
                    cmd_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                    del_btn = QPushButton("✕", row_w)
                    del_btn.setFixedSize(22, 22)
                    row_h.addWidget(name_lbl)
                    row_h.addWidget(cmd_lbl)
                    row_h.addWidget(del_btn)
                    scroll_layout.addWidget(row_w)

                    def _on_delete(checked=False, _p=p):
                        all_presets = _load_presets()
                        updated = [x for x in all_presets
                                   if not (x.get("name") == _p.get("name")
                                           and x.get("category") == _p.get("category"))]
                        _save_presets(updated)
                        _refresh_custom_combo()
                        _build_list()

                    del_btn.clicked.connect(_on_delete)

            scroll_layout.addStretch(1)

        _build_list()

        sep2 = QFrame(dlg)
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(sep2)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        close_btn = QPushButton("Close", dlg)
        close_btn.setFixedWidth(80)
        close_btn.clicked.connect(dlg.accept)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)
        dlg.exec()

    def _on_options_clicked():
        menu = QMenu(chat_panel)
        menu.setStyleSheet(getattr(c, "menu_stylesheet", ""))
        act_add = QAction("Add new command", menu)
        act_manage = QAction("View / Remove commands", menu)
        menu.addAction(act_add)
        menu.addAction(act_manage)
        act_add.triggered.connect(_open_add_dialog)
        act_manage.triggered.connect(_open_manage_dialog)
        menu.exec(chat_btn_add.mapToGlobal(chat_btn_add.rect().bottomLeft()))

    chat_combo_interface.currentIndexChanged.connect(lambda: _refresh_custom_combo())
    chat_combo_custom.currentIndexChanged.connect(lambda: _on_custom_changed())
    chat_btn_add.clicked.connect(_on_options_clicked)

    # Load presets on startup
    _refresh_custom_combo()

    # Register reload hook so menu_builder can trigger refresh after profile save
    c.register_widget("chat_combo_custom_reload", _refresh_custom_combo)

    # ── Info dialog ───────────────────────────────────────────────────────────

    chat_info_dialog = QDialog(chat_panel)
    chat_info_dialog.setWindowTitle("Info")
    chat_info_dlg_layout = QVBoxLayout(chat_info_dialog)
    chat_info_dlg_layout.setContentsMargins(12, 12, 12, 12)
    chat_info_dlg_layout.setSpacing(8)

    info_cmd_label = QPlainTextEdit(chat_info_dialog)
    info_cmd_label.setObjectName("script_term")
    info_cmd_label.setReadOnly(True)
    info_cmd_label.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
    info_cmd_label.setFixedHeight(72)
    info_cmd_label.hide()
    chat_info_dlg_layout.addWidget(info_cmd_label)

    info_separator = QFrame(chat_info_dialog)
    info_separator.setFrameShape(QFrame.Shape.HLine)
    info_separator.setFrameShadow(QFrame.Shadow.Sunken)
    info_separator.hide()
    chat_info_dlg_layout.addWidget(info_separator)

    server_log_label = QLabel("No active logs.", chat_info_dialog)
    server_log_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    chat_info_dlg_layout.addWidget(server_log_label)

    _info_term_container = QWidget(chat_info_dialog)
    _info_term_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    _info_term_layout = QVBoxLayout(_info_term_container)
    _info_term_layout.setContentsMargins(0, 0, 0, 0)
    _info_term_container.hide()
    chat_info_dlg_layout.addWidget(_info_term_container)

    _info_term = [None]

    chat_btn_info.clicked.connect(chat_info_dialog.exec)

    c.register_widget("chat_panel", chat_panel)
    c.register_widget("chat_panel_layout", chat_panel_layout)
    c.register_widget("chat_future_label", future_label)
    c.register_widget("chat_combo_interface", chat_combo_interface)
    c.register_widget("chat_combo_custom", chat_combo_custom)
    c.register_widget("chat_btn_add", chat_btn_add)
    c.register_widget("chat_btn_info", chat_btn_info)
    c.register_widget("chat_cmd_preview", cmd_preview_edit)
    c.register_widget("chat_info_cmd_label", info_cmd_label)
    c.register_widget("chat_btn_run", chat_btn_run)
    c.register_widget("chat_btn_run_menu", _run_mode_menu)
    c.register_widget("chat_info_dialog", chat_info_dialog)

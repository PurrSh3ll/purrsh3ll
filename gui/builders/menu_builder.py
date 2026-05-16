from PyQt6.QtWidgets import (
    QPushButton, QDialog, QFormLayout, QHBoxLayout, QVBoxLayout,
    QLabel, QSpinBox, QCheckBox, QLineEdit, QComboBox, QGroupBox, QScrollArea, QWidget,
    QRadioButton, QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QAction, QIntValidator
import os
import json
import subprocess

from core.controller import controller_instance


c = controller_instance

def build_menu(main_window):

    menu_button = QPushButton("⋯", c.widgets["central_widget"])
    menu_button.setGeometry(10, 0, 40, 12)
    c.register_widget("menu_button", menu_button)

    menu_bar = main_window.menuBar()
    menu_bar.setVisible(False)
    c.register_widget("menu_bar", menu_bar)

    file_menu = menu_bar.addMenu("File")
    settings_action = QAction("Settings", main_window)
    file_menu.addAction(settings_action)
    c.register_widget("settings_action", settings_action)
    ai_settings_action = QAction("AI Settings", main_window)
    file_menu.addAction(ai_settings_action)
    c.register_widget("ai_settings_action", ai_settings_action)
    open_file_action = QAction("Open File", main_window)
    open_file_action.setShortcut("Ctrl+O")
    file_menu.addAction(open_file_action)
    c.register_widget("open_file_action", open_file_action)
    exit_action = QAction("Exit", main_window)
    file_menu.addAction(exit_action)
    c.register_widget("file_menu", file_menu)
    c.register_widget("exit_action", exit_action)

    edit_menu = menu_bar.addMenu("Edit")
    command_palette_action = QAction("Command Palette", main_window)
    command_palette_action.setShortcut("Ctrl+P")
    edit_menu.addAction(command_palette_action)
    c.register_widget("edit_menu", edit_menu)
    c.register_widget("command_palette_action", command_palette_action)

    view_menu = menu_bar.addMenu("View")
    change_theme_menu = view_menu.addMenu("Change Theme")
    for theme_name in c.themes:
        theme_action = QAction(theme_name, main_window)
        change_theme_menu.addAction(theme_action)
        c.register_widget(f"{theme_name}_theme", theme_action)
    c.register_widget("view_menu", view_menu)
    c.register_widget("change_theme_menu", change_theme_menu)

    author_action = QAction("Author", main_window)
    menu_bar.addAction(author_action)
    help_menu = menu_bar.addMenu("Help")
    c.register_widget("help_menu", help_menu)
    c.register_widget("author_action", author_action)

    user_guide_action = QAction("User Guide", main_window)
    manual_action = QAction("Manual", main_window)
    about_qt_action = QAction("About Qt", main_window)
    about_qterm_action = QAction("About QTerm", main_window)
    about_licenses_action = QAction("Licenses", main_window)
    help_menu.addAction(user_guide_action)
    help_menu.addAction(manual_action)
    help_menu.addAction(about_qt_action)
    help_menu.addAction(about_qterm_action)
    help_menu.addAction(about_licenses_action)
    c.register_widget("user_guide_action", user_guide_action)
    c.register_widget("manual_action", manual_action)
    c.register_widget("about_qt_action", about_qt_action)
    c.register_widget("about_qterm_action", about_qterm_action)
    c.register_widget("about_licenses_action", about_licenses_action)

    def _auto_hide_menu_bar():
        if QApplication.activePopupWidget() is None:
            menu_bar.setVisible(False)
            menu_button.setVisible(True)

    for _m in (file_menu, edit_menu, view_menu, help_menu):
        _m.aboutToHide.connect(lambda: QTimer.singleShot(50, _auto_hide_menu_bar))

    author_action.triggered.connect(lambda: QTimer.singleShot(50, _auto_hide_menu_bar))

    def create_settings_dialog():
        settings_path = getattr(c, "config_path", None)
        data = {}
        if settings_path:
            try:
                if os.path.exists(settings_path):
                    with open(settings_path, "r", encoding="utf-8") as f:
                        data = json.load(f) or {}
            except Exception:
                data = {}

        w_default, h_default = 800, 600
        try:
            if "window" in data and isinstance(data["window"].get("resolution"), list):
                w_default, h_default = map(int, data["window"]["resolution"])
            elif hasattr(c, "width") and hasattr(c, "height"):
                w_default, h_default = int(c.width), int(c.height)
        except Exception:
            w_default, h_default = 800, 600

        x_default, y_default = 100, 100
        try:
            if "window" in data and isinstance(data["window"].get("start_screen"), list):
                x_default, y_default = map(int, data["window"]["start_screen"])
            elif hasattr(c, "start_x") and hasattr(c, "start_y"):
                x_default, y_default = int(c.start_x), int(c.start_y)
        except Exception:
            x_default, y_default = 100, 100

        lw_default = False
        try:
            if "performance" in data and "lightweight_web_browser" in data["performance"]:
                lw_default = bool(data["performance"]["lightweight_web_browser"])
            elif hasattr(main_window, "_controller") and getattr(main_window._controller, "lightweight_web_browser", None) is not None:
                lw_default = bool(main_window._controller.lightweight_web_browser)
        except Exception:
            lw_default = False

        dlg = QDialog(main_window)
        dlg.setWindowTitle("Settings")
        dlg.setModal(True)
        dlg.setMinimumWidth(460)
        dlg.resize(480, 420)

        # ── Window group ──────────────────────────────────────────────────────
        grp_window = QGroupBox("Window")
        form_window = QFormLayout(grp_window)
        form_window.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        width_spin = QSpinBox(grp_window)
        width_spin.setRange(100, 10000)
        height_spin = QSpinBox(grp_window)
        height_spin.setRange(100, 10000)
        width_spin.setValue(w_default)
        height_spin.setValue(h_default)
        res_row = QHBoxLayout()
        res_row.addWidget(width_spin)
        res_row.addWidget(QLabel("×", grp_window))
        res_row.addWidget(height_spin)
        form_window.addRow("Resolution:", res_row)

        x_spin = QSpinBox(grp_window)
        x_spin.setRange(-10000, 10000)
        y_spin = QSpinBox(grp_window)
        y_spin.setRange(-10000, 10000)
        x_spin.setValue(x_default)
        y_spin.setValue(y_default)
        start_row = QHBoxLayout()
        start_row.addWidget(x_spin)
        start_row.addWidget(QLabel(",", grp_window))
        start_row.addWidget(y_spin)
        form_window.addRow("Start position:", start_row)

        # ── Behavior group ────────────────────────────────────────────────────
        grp_behavior = QGroupBox("Behavior")
        form_behavior = QFormLayout(grp_behavior)
        form_behavior.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        lw_checkbox = QCheckBox("Lightweight browser", grp_behavior)
        lw_checkbox.setChecked(lw_default)
        form_behavior.addRow(lw_checkbox)

        restore_session_checkbox = QCheckBox("Restore session on startup", grp_behavior)
        restore_session_checkbox.setChecked(getattr(c, 'session_restore_enabled', True))
        form_behavior.addRow(restore_session_checkbox)

        save_sys_checkbox = QCheckBox("Save system variables on exit", grp_behavior)
        save_sys_checkbox.setChecked(c.save_system_vars)
        form_behavior.addRow(save_sys_checkbox)

        delete_logs_checkbox = QCheckBox("Clear terminal history on exit", grp_behavior)
        delete_logs_checkbox.setChecked(c.delete_logs_at_close)
        form_behavior.addRow(delete_logs_checkbox)

        delete_notes_checkbox = QCheckBox("Clear notes on exit", grp_behavior)
        delete_notes_checkbox.setChecked(c.delete_notes_at_close)
        form_behavior.addRow(delete_notes_checkbox)

        disable_history_checkbox = QCheckBox("Disable terminal history", grp_behavior)
        disable_history_checkbox.setChecked(getattr(c, "terminal_history_disabled", False))
        form_behavior.addRow(disable_history_checkbox)

        _HISTORY_MAX_DEFAULT = 5000
        _history_max_saved = getattr(c, "terminal_history_max_entries", _HISTORY_MAX_DEFAULT)
        history_max_spin = QSpinBox(grp_behavior)
        history_max_spin.setRange(100, 100000)
        history_max_spin.setValue(int(_history_max_saved))
        history_max_reset_btn = QPushButton("Default", grp_behavior)
        history_max_reset_btn.setFixedWidth(60)
        history_max_row = QHBoxLayout()
        history_max_row.addWidget(history_max_spin)
        history_max_row.addWidget(history_max_reset_btn)
        form_behavior.addRow("Max history entries:", history_max_row)

        # ── Signal handlers ───────────────────────────────────────────────────
        def _save_behavior_key(key, value):
            if not os.path.exists(c.config_path):
                return
            try:
                with open(c.config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                config.setdefault("behavior", {})[key] = value
                with open(c.config_path, "w", encoding="utf-8") as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
            except Exception:
                pass

        def _on_save_sys_changed(state):
            c.save_system_vars = save_sys_checkbox.isChecked()
            _save_behavior_key("save_sys_vars_at_close", c.save_system_vars)

        def _on_delete_logs_changed(state):
            c.delete_logs_at_close = delete_logs_checkbox.isChecked()
            _save_behavior_key("delete_logs_at_close", c.delete_logs_at_close)

        def _on_delete_notes_changed(state):
            c.delete_notes_at_close = delete_notes_checkbox.isChecked()
            _save_behavior_key("delete_notes_at_close", c.delete_notes_at_close)

        def _on_restore_session_changed(state):
            c.session_restore_enabled = restore_session_checkbox.isChecked()
            _save_behavior_key("restore_session_at_start", c.session_restore_enabled)

        def _on_disable_history_changed(state):
            c.terminal_history_disabled = disable_history_checkbox.isChecked()
            _save_behavior_key("terminal_history_disabled", c.terminal_history_disabled)

        def _on_history_max_changed(value):
            c.terminal_history_max_entries = value
            _save_behavior_key("terminal_history_max_entries", value)

        def _on_history_max_reset():
            history_max_spin.setValue(_HISTORY_MAX_DEFAULT)

        save_sys_checkbox.stateChanged.connect(_on_save_sys_changed)
        delete_logs_checkbox.stateChanged.connect(_on_delete_logs_changed)
        delete_notes_checkbox.stateChanged.connect(_on_delete_notes_changed)
        restore_session_checkbox.stateChanged.connect(_on_restore_session_changed)
        disable_history_checkbox.stateChanged.connect(_on_disable_history_changed)
        history_max_spin.valueChanged.connect(_on_history_max_changed)
        history_max_reset_btn.clicked.connect(_on_history_max_reset)

        # ── Register widgets ──────────────────────────────────────────────────
        try:
            c.register_widget("settings_dialog", dlg)
            c.register_widget("settings_width_spin", width_spin)
            c.register_widget("settings_height_spin", height_spin)
            c.register_widget("settings_x_spin", x_spin)
            c.register_widget("settings_y_spin", y_spin)
            c.register_widget("settings_lw_checkbox", lw_checkbox)
            c.register_widget("settings_save_sys_checkbox", save_sys_checkbox)
            c.register_widget("settings_delete_logs_checkbox", delete_logs_checkbox)
            c.register_widget("settings_delete_notes_checkbox", delete_notes_checkbox)
            c.register_widget("settings_restore_session_checkbox", restore_session_checkbox)
            c.register_widget("settings_history_max_spin", history_max_spin)
            c.register_widget("settings_scroll",         scroll)
            c.register_widget("settings_scroll_content", scroll_content)
        except Exception:
            pass

        # ── OK / Cancel ───────────────────────────────────────────────────────
        btn_ok = QPushButton("OK", dlg)
        btn_cancel = QPushButton("Cancel", dlg)

        def _apply_and_close():
            w = width_spin.value()
            h = height_spin.value()
            x = x_spin.value()
            y = y_spin.value()
            lw = bool(lw_checkbox.isChecked())

            new_data = {}
            try:
                if settings_path and os.path.exists(settings_path):
                    try:
                        with open(settings_path, "r", encoding="utf-8") as f:
                            new_data = json.load(f) or {}
                    except Exception:
                        new_data = {}

                new_data.setdefault("window", {})
                new_data.setdefault("performance", {})
                new_data.setdefault("user_profile", {})
                new_data["window"]["resolution"] = [w, h]
                new_data["window"]["start_screen"] = [x, y]
                new_data["window"].setdefault("fullscreen", False)
                new_data["performance"]["lightweight_web_browser"] = lw
                if settings_path:
                    try:
                        with open(settings_path, "w", encoding="utf-8") as f:
                            json.dump(new_data, f, indent=2, ensure_ascii=False)
                    except Exception:
                        pass

            except Exception:
                pass

            c.width = w
            c.height = h
            c.start_x = x
            c.start_y = y
            c.lightweight_web_browser = lw

            dlg.accept()

        btn_ok.clicked.connect(_apply_and_close)
        btn_cancel.clicked.connect(dlg.reject)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch(1)
        btn_layout.addWidget(btn_ok)
        btn_layout.addWidget(btn_cancel)

        # ── Assemble dialog ───────────────────────────────────────────────────
        scroll_content = QWidget()
        scroll_content.setObjectName("settings_scroll_content")
        scroll_content.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(4, 4, 4, 4)
        scroll_layout.setSpacing(8)
        scroll_layout.addWidget(grp_window)
        scroll_layout.addWidget(grp_behavior)
        scroll_layout.addStretch(1)

        scroll = QScrollArea(dlg)
        scroll.setObjectName("settings_scroll")
        scroll.setWidgetResizable(True)
        scroll.setWidget(scroll_content)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        main_layout = QVBoxLayout(dlg)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)
        main_layout.addWidget(scroll)
        main_layout.addLayout(btn_layout)

    def create_about_qterm_dialog():
        qterminal_dialog = QDialog()
        qterminal_dialog.setWindowTitle("QTerminal Info")
        qterminal_dialog.setModal(True)
        layout = QVBoxLayout()
        qterminal_label = QLabel("""
        <div style="text-align: center;">
            <b>QTerminal 2.1.0</b><br><br>
            A lightweight and powerful multiplatform terminal emulator<br><br>
            Copyright (C) 2013-2026<br>
            <a href="https://lxqt-project.org/">LXQt Project</a><br><br>
            Development:<br>
            <a href="https://github.com/lxqt/qterminal">
                https://github.com/lxqt/qterminal
            </a>
        </div>
        """)
        qterminal_label.setTextFormat(Qt.TextFormat.RichText)
        qterminal_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        qterminal_label.setOpenExternalLinks(True)
        layout.addWidget(qterminal_label)
        qterminal_dialog.setLayout(layout)
        qterminal_dialog.resize(400, 220)
        try:
            c.register_widget("qterminal_dialog", qterminal_dialog)
            c.register_widget("qterminal_label", qterminal_label)
        except Exception as e:
            pass

    def create_licenses_dialog():
        licenses_dialog = QDialog()
        licenses_dialog.setWindowTitle("Licenses")
        licenses_dialog.setModal(True)
        layout = QVBoxLayout()
        licenses_label = QLabel("""
        <div style="text-align: left; padding: 8px;">
            <div style="text-align: center;"><b>Licenses and Dependencies</b></div><br>

            <b>Python Libraries</b><br>
            • <a href="https://pypi.org/project/PyQt6/">PyQt6 6.10.0</a> – GPL v3<br>
            • <a href="https://pypi.org/project/PyQt6-WebEngine/">PyQt6-WebEngine 6.10.0</a> – GPL v3<br>
            • <a href="https://pypi.org/project/pyqt6-sip/">pyqt6-sip 13.10.2</a> – GPL / MIT<br>
            • <a href="https://pypi.org/project/QtPy/">QtPy 2.4.3</a> – MIT<br>
            • <a href="https://github.com/lxqt/qtermwidget/">QTermWidget 2.2.0</a> – GPL v2<br>
            • <a href="https://pypi.org/project/watchdog/">watchdog 6.0.0</a> – Apache 2.0<br>
            • <a href="https://pypi.org/project/chromadb/">chromadb 1.5.9</a> – Apache 2.0<br>
            • <a href="https://pypi.org/project/fastembed/">fastembed 0.8.0</a> – Apache 2.0<br>
            • <a href="https://pypi.org/project/onnxruntime/">onnxruntime 1.26.0</a> – MIT<br>
            • <a href="https://pypi.org/project/huggingface-hub/">huggingface-hub 1.14.0</a> – Apache 2.0<br>
            • <a href="https://pypi.org/project/keyring/">keyring 25.7.0</a> – MIT<br>
            • <a href="https://pypi.org/project/SecretStorage/">SecretStorage 3.5.0</a> – BSD 3-Clause<br>
            • <a href="https://pypi.org/project/cryptography/">cryptography 46.0.5</a> – Apache 2.0 / BSD<br>
            • <a href="https://pypi.org/project/docker/">docker 7.1.0</a> – Apache 2.0<br>
            • <a href="https://pypi.org/project/pyfiglet/">pyfiglet 1.0.4</a> – MIT<br>
            • <a href="https://pypi.org/project/pygame/">pygame 2.6.1</a> – LGPL v2.1<br>
            • <a href="https://pypi.org/project/Pillow/">Pillow 12.0.0</a> – HPND<br>
            • <a href="https://pypi.org/project/pydantic/">pydantic 2.13.4</a> – MIT<br>
            • <a href="https://pypi.org/project/requests/">requests 2.32.5</a> – Apache 2.0<br>
            • <a href="https://pypi.org/project/PyYAML/">PyYAML 6.0.3</a> – MIT<br>
            • <a href="https://pypi.org/project/loguru/">loguru 0.7.3</a> – MIT<br>
            • <a href="https://pypi.org/project/rich/">rich 14.2.0</a> – MIT<br>
            • <a href="https://pypi.org/project/numpy/">numpy 2.4.4</a> – BSD 3-Clause<br>
            • <a href="https://pypi.org/project/pyte/">pyte 0.8.2</a> – LGPL v3<br>
            • <a href="https://pypi.org/project/markdown2/">markdown2 2.5.4</a> – MIT<br>
            • <a href="https://pypi.org/project/Pygments/">Pygments 2.19.2</a> – BSD 2-Clause<br>
            • <a href="https://pypi.org/project/jeepney/">jeepney 0.9.0</a> – MIT<br><br>

            <hr>
            <b>External Tools &amp; Resources</b><br>
            • <a href="https://github.com/ollama/ollama">Ollama</a> – MIT<br>
            • <a href="https://github.com/sigoden/aichat">aichat</a> – MIT<br>
            • <a href="https://github.com/SabyasachiRana/WebMap">WebMap</a> – MIT<br>
            • <a href="https://github.com/open-webui/open-webui">Open WebUI</a> – BSD 3-Clause<br>
            • <a href="https://github.com/cr-gpt/awesome-claude-code-skills-security">awesome-claude-skills-security</a> – MIT<br>
            • <a href="https://github.com/anthropics/claude-code">claude-code-pentest skills</a> – MIT<br><br>

            <hr>
            <div style="text-align: center; color: gray; font-size: 11px;">
                Full license texts are available at the respective project links.
            </div>
        </div>
        """)
        licenses_label.setTextFormat(Qt.TextFormat.RichText)
        licenses_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        licenses_label.setOpenExternalLinks(True)
        licenses_label.setWordWrap(True)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(licenses_label)

        layout.addWidget(scroll)
        licenses_dialog.setLayout(layout)
        licenses_dialog.resize(580, 520)
        try:
            c.register_widget("licenses_dialog", licenses_dialog)
            c.register_widget("licenses_label", licenses_label)
        except Exception as e:
            pass

    def create_about_qt_dialog():
        qt_dialog = QDialog()
        qt_dialog.setWindowTitle("About Qt")
        qt_dialog.setModal(True)
        layout = QVBoxLayout()
        qt_label = QLabel("""
        <div style="text-align: center;">
            <b>Qt version 6.10.2</b><br><br>
            Qt is a C++ toolkit for cross-platform application development.<br><br>
            Qt provides single-source portability across all major desktop operating systems.
            It is also available for embedded Linux and other embedded and mobile operating systems.<br><br>
            Qt is available under multiple licensing options designed to accommodate the needs of our various users.<br><br>
            Qt licensed under our commercial license agreement is appropriate for development of proprietary/commercial software
            where you do not want to share any source code with third parties or otherwise cannot comply with the terms of GNU (L)GPL.<br><br>
            Qt licensed under GNU (L)GPL is appropriate for the development of Qt applications provided you can comply with the terms
            and conditions of the respective licenses.<br><br>
            Please see <a href="https://qt.io/licensing">qt.io/licensing</a> for an overview of Qt licensing.<br><br>
            Copyright (C) The Qt Company Ltd. and other contributors.<br>
            Qt and the Qt logo are trademarks of The Qt Company Ltd.<br><br>
            Qt is The Qt Company Ltd. product developed as an open source project.<br>
            See <a href="https://qt.io">qt.io</a> for more information.
        </div>
        """)
        qt_label.setTextFormat(Qt.TextFormat.RichText)
        qt_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        qt_label.setOpenExternalLinks(True)
        qt_label.setWordWrap(True)
        layout.addWidget(qt_label)
        qt_dialog.setLayout(layout)
        qt_dialog.resize(500, 400)
        try:
            c.register_widget("qt_dialog", qt_dialog)
            c.register_widget("qt_label", qt_label)
        except Exception as e:
            pass

    def create_ai_settings_dialog():
        settings_path = getattr(c, "config_path", None)
        data = {}
        if settings_path:
            try:
                if os.path.exists(settings_path):
                    with open(settings_path, "r", encoding="utf-8") as f:
                        data = json.load(f) or {}
            except Exception:
                data = {}

        llama_cfg = data.get("llama", {})
        llm_cli_default       = llama_cfg.get("llm_cli_path", "")
        logs_terminal_default = llama_cfg.get("logs_terminal_cmd", "")

        dlg = QDialog(main_window)
        dlg.setWindowTitle("AI Settings")
        dlg.setModal(True)
        dlg.setMinimumWidth(460)
        dlg.resize(480, 600)

        def _make_path_row(parent, default_val, config_key):
            edit = QLineEdit(parent)
            edit.setText(default_val)
            edit.setReadOnly(True)
            btn = QPushButton("Edit", parent)
            btn.setFixedWidth(44)
            row = QHBoxLayout()
            row.addWidget(edit)
            row.addWidget(btn)

            def _on_edit(checked=False, e=edit, k=config_key):
                popup = QDialog(dlg)
                popup.setWindowTitle("Edit value")
                popup_layout = QVBoxLayout(popup)
                popup_layout.setContentsMargins(10, 10, 10, 10)
                popup_layout.setSpacing(6)
                popup_edit = QLineEdit(popup)
                popup_edit.setText(e.text())
                popup_layout.addWidget(popup_edit)
                popup_ok = QPushButton("OK", popup)
                popup_layout.addWidget(popup_ok, alignment=Qt.AlignmentFlag.AlignRight)

                def _confirm():
                    val = popup_edit.text()
                    e.setText(val)
                    try:
                        cfg = {}
                        if os.path.exists(c.config_path):
                            with open(c.config_path, "r", encoding="utf-8") as f:
                                cfg = json.load(f) or {}
                        cfg.setdefault("llama", {})[k] = val
                        with open(c.config_path, "w", encoding="utf-8") as f:
                            json.dump(cfg, f, indent=2, ensure_ascii=False)
                    except Exception:
                        pass
                    popup.accept()

                popup_ok.clicked.connect(_confirm)
                popup.exec()

            btn.clicked.connect(_on_edit)
            return edit, row

        # ── AI / LLM group ────────────────────────────────────────────────────
        grp_llm = QGroupBox("AI / LLM")
        form_llm = QFormLayout(grp_llm)
        form_llm.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        llm_cli_edit,       llm_cli_row       = _make_path_row(grp_llm, llm_cli_default,       "llm_cli_path")
        logs_terminal_edit, logs_terminal_row = _make_path_row(grp_llm, logs_terminal_default, "logs_terminal_cmd")

        form_llm.addRow("LLM CLI path:",       llm_cli_row)
        form_llm.addRow("Agent run command:", logs_terminal_row)

        _base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _agent_modes_dir = os.path.join(_base_dir, "appdata", "agent_modes", "agent_md")
        _skills_dir = os.path.join(_base_dir, "appdata", "agent_modes", "skills")

        _agent_roles = []
        try:
            if os.path.isdir(_agent_modes_dir):
                _agent_roles = sorted(os.listdir(_agent_modes_dir))
        except Exception:
            pass
        settings_agent_role_combo = QComboBox(grp_llm)
        settings_agent_role_combo.addItem("none")
        settings_agent_role_combo.addItems(_agent_roles)
        _saved_agent_role = llama_cfg.get("agent_role", "")
        if _saved_agent_role in _agent_roles:
            settings_agent_role_combo.setCurrentText(_saved_agent_role)
        form_llm.addRow("Agent role:", settings_agent_role_combo)

        _skills = []
        try:
            if os.path.isdir(_skills_dir):
                _skills = sorted(os.listdir(_skills_dir))
        except Exception:
            pass
        settings_skills_combo = QComboBox(grp_llm)
        settings_skills_combo.addItem("none")
        settings_skills_combo.addItems(_skills)
        _saved_skills = llama_cfg.get("skills_set", "")
        if _saved_skills in _skills:
            settings_skills_combo.setCurrentText(_saved_skills)
        form_llm.addRow("Skills set:", settings_skills_combo)

        _ai_think_saved = llama_cfg.get("ai_disable_thinking",
                          llama_cfg.get("ollama_disable_thinking", False))
        _ai_fast_saved  = llama_cfg.get("ai_fast_answers",
                          llama_cfg.get("ollama_fast_answers", False))
        ai_think_cb = QCheckBox("Disable thinking", grp_llm)
        ai_fast_cb  = QCheckBox("Fast answers  (short responses)", grp_llm)
        ai_think_cb.setChecked(bool(_ai_think_saved))
        ai_fast_cb.setChecked(bool(_ai_fast_saved))
        ai_opts_row = QHBoxLayout()
        ai_opts_row.addWidget(ai_think_cb)
        ai_opts_row.addSpacing(16)
        ai_opts_row.addWidget(ai_fast_cb)
        ai_opts_row.addStretch(1)
        form_llm.addRow("Model options:", ai_opts_row)

        # ── RAG group ─────────────────────────────────────────────────────────
        grp_rag = QGroupBox("RAG")
        form_rag = QFormLayout(grp_rag)
        form_rag.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        _rag_cfg = data.get("rag", {})
        _rag_mode = _rag_cfg.get("knowledge_base", "braindump")
        _rag_custom_path = _rag_cfg.get("custom_path", "")

        _RAG_MODELS = [
            ("paraphrase-multilingual-MiniLM-L12-v2 (120MB, PL+EN)",
             "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"),
            ("bge-small-en-v1.5 (33MB, EN)",
             "BAAI/bge-small-en-v1.5"),
            ("bge-base-en-v1.5 (109MB, EN)",
             "BAAI/bge-base-en-v1.5"),
            ("nomic-embed-text-v1.5 (274MB, EN)",
             "nomic-ai/nomic-embed-text-v1.5"),
        ]
        _DEFAULT_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
        _saved_model   = _rag_cfg.get("embedding_model", _DEFAULT_MODEL)

        _base_dir_rag = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _braindump_path = os.path.join(
            getattr(c, "app_modules_path", os.path.join(_base_dir_rag, "appmodules")),
            "BrainDump"
        )

        rag_radio_braindump = QRadioButton("BrainDump", grp_rag)
        rag_radio_custom    = QRadioButton("Custom",    grp_rag)
        rag_radio_braindump.setChecked(_rag_mode != "custom")
        rag_radio_custom.setChecked(_rag_mode == "custom")

        rag_radio_row = QHBoxLayout()
        rag_radio_row.setSpacing(12)
        rag_radio_row.addWidget(rag_radio_braindump)
        rag_radio_row.addWidget(rag_radio_custom)
        rag_radio_row.addStretch(1)
        form_rag.addRow("Knowledge base:", rag_radio_row)

        rag_path_edit = QLineEdit(grp_rag)
        rag_path_edit.setPlaceholderText("Select folder…")
        rag_path_edit.setReadOnly(True)
        rag_path_edit.setText(
            _rag_custom_path if _rag_mode == "custom" else _braindump_path
        )
        rag_path_edit.setEnabled(_rag_mode == "custom")

        rag_browse_btn = QPushButton("Browse", grp_rag)
        rag_browse_btn.setFixedWidth(60)
        rag_browse_btn.setVisible(_rag_mode == "custom")

        rag_path_row = QHBoxLayout()
        rag_path_row.addWidget(rag_path_edit)
        rag_path_row.addWidget(rag_browse_btn)
        form_rag.addRow("Path:", rag_path_row)

        rag_model_combo = QComboBox(grp_rag)
        for _label, _val in _RAG_MODELS:
            rag_model_combo.addItem(_label, _val)
        _saved_idx = next(
            (i for i, (_, v) in enumerate(_RAG_MODELS) if v == _saved_model), 0
        )
        rag_model_combo.setCurrentIndex(_saved_idx)
        form_rag.addRow("Embedding model:", rag_model_combo)

        _rag_auto_index = _rag_cfg.get("auto_index", False)
        rag_auto_checkbox = QCheckBox("Enable automatic indexing", grp_rag)
        rag_auto_checkbox.setChecked(bool(_rag_auto_index))

        rag_reindex_btn = QPushButton("⟳ Refresh index", grp_rag)
        rag_reindex_btn.setFixedWidth(110)

        rag_delete_btn = QPushButton("🗑 Delete vector DB", grp_rag)
        rag_delete_btn.setFixedWidth(130)

        rag_index_row = QHBoxLayout()
        rag_index_row.addWidget(rag_auto_checkbox)
        rag_index_row.addStretch(1)
        rag_index_row.addWidget(rag_reindex_btn)
        rag_index_row.addWidget(rag_delete_btn)
        form_rag.addRow("Indexing:", rag_index_row)

        rag_status_label = QLabel("", grp_rag)
        rag_status_label.setStyleSheet("color: gray; font-size: 11px;")
        rag_status_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse |
            Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        rag_status_label.setWordWrap(True)
        form_rag.addRow("Status:", rag_status_label)

        def _save_rag_key(key, value):
            if not os.path.exists(c.config_path):
                return
            try:
                with open(c.config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                cfg.setdefault("rag", {})[key] = value
                with open(c.config_path, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
            except Exception:
                pass

        def _save_llama_key(key, value):
            if not os.path.exists(c.config_path):
                return
            try:
                with open(c.config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                config.setdefault("llama", {})[key] = value
                with open(c.config_path, "w", encoding="utf-8") as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
            except Exception:
                pass

        def _restart_watcher_if_active():
            if rag_auto_checkbox.isChecked():
                c.start_rag_watcher()

        def _on_rag_braindump_toggled(checked):
            if not checked:
                return
            rag_path_edit.setText(_braindump_path)
            rag_path_edit.setEnabled(False)
            rag_browse_btn.setVisible(False)
            _save_rag_key("knowledge_base", "braindump")
            _restart_watcher_if_active()

        def _on_rag_custom_toggled(checked):
            if not checked:
                return
            rag_path_edit.setEnabled(True)
            rag_browse_btn.setVisible(True)
            _save_rag_key("knowledge_base", "custom")
            _restart_watcher_if_active()

        def _on_rag_browse():
            from PyQt6.QtWidgets import QFileDialog, QMessageBox
            folder = QFileDialog.getExistingDirectory(
                dlg, "Select Knowledge Base Folder",
                rag_path_edit.text() or _base_dir_rag
            )
            if not folder:
                return
            if folder == rag_path_edit.text():
                return
            reply = QMessageBox.question(
                dlg,
                "Change Knowledge Base",
                f"Changing the knowledge base folder will delete the current\n"
                f"vector database and re-index from scratch.\n\n"
                f"New path:\n{folder}\n\nContinue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
            import shutil
            _rag_dir = os.path.join(getattr(c, "base_path", _base_dir_rag), "appdata", "rag")
            for _target in (
                os.path.join(_rag_dir, "chroma_db"),
                os.path.join(_rag_dir, "index_meta.json"),
            ):
                try:
                    if os.path.isdir(_target):
                        shutil.rmtree(_target)
                    elif os.path.isfile(_target):
                        os.remove(_target)
                except Exception:
                    pass
            rag_path_edit.setText(folder)
            _save_rag_key("custom_path", folder)
            _restart_watcher_if_active()
            _on_rag_reindex()

        def _on_rag_model_changed(idx):
            new_model = rag_model_combo.itemData(idx)
            if new_model == _saved_model:
                return
            from PyQt6.QtWidgets import QMessageBox
            reply = QMessageBox.question(
                dlg,
                "Change Embedding Model",
                "Changing the embedding model requires deleting the current\n"
                "vector database and re-indexing from scratch.\n\n"
                "This may take a while if the new model needs to be downloaded.\n\nContinue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                prev_idx = next(
                    (i for i, (_, v) in enumerate(_RAG_MODELS) if v == _saved_model), 0
                )
                rag_model_combo.blockSignals(True)
                rag_model_combo.setCurrentIndex(prev_idx)
                rag_model_combo.blockSignals(False)
                return
            import shutil
            _rag_dir = os.path.join(getattr(c, "base_path", _base_dir_rag), "appdata", "rag")
            for _target in (
                os.path.join(_rag_dir, "chroma_db"),
                os.path.join(_rag_dir, "index_meta.json"),
            ):
                try:
                    if os.path.isdir(_target):
                        shutil.rmtree(_target)
                    elif os.path.isfile(_target):
                        os.remove(_target)
                except Exception:
                    pass
            _save_rag_key("embedding_model", new_model)
            _on_rag_reindex()

        def _on_rag_auto_index_changed(state):
            enabled = rag_auto_checkbox.isChecked()
            _save_rag_key("auto_index", enabled)
            if enabled:
                c.start_rag_watcher()
            else:
                c.stop_rag_watcher()

        _spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        _spinner_idx = [0]

        def _on_rag_reindex():
            kb_path = rag_path_edit.text().strip()
            if not kb_path or not os.path.isdir(kb_path):
                from PyQt6.QtWidgets import QMessageBox
                QMessageBox.warning(dlg, "RAG", "Knowledge base folder not found.\nCheck the path in AI Settings > RAG.")
                return
            model_name = rag_model_combo.currentData()
            from core.rag.index_worker import IndexWorker
            worker = IndexWorker(kb_path, getattr(c, "base_path", ""), model_name)
            c._rag_index_worker = worker
            rag_reindex_btn.setEnabled(False)
            rag_delete_btn.setEnabled(False)
            rag_status_label.setText("Starting…")
            spinner_timer = QTimer(dlg)
            spinner_timer.setInterval(100)

            def _tick():
                _spinner_idx[0] = (_spinner_idx[0] + 1) % len(_spinner_frames)
                rag_reindex_btn.setText(_spinner_frames[_spinner_idx[0]])

            spinner_timer.timeout.connect(_tick)
            spinner_timer.start()

            def _on_progress(current, total, filename):
                short = filename[:28] + "…" if len(filename) > 30 else filename
                rag_status_label.setText(f"{current}/{total}  {short}")

            def _on_finished(result):
                spinner_timer.stop()
                rag_reindex_btn.setText("⟳ Refresh index")
                rag_reindex_btn.setEnabled(True)
                rag_delete_btn.setEnabled(True)
                if result == "OK":
                    rag_status_label.setText("✔ Indexing complete.")
                    rag_status_label.setStyleSheet("color: green; font-size: 11px;")
                else:
                    rag_status_label.setText(f"✖ {result}")
                    rag_status_label.setStyleSheet("color: red; font-size: 11px;")
                c._rag_index_worker = None

            worker.progress.connect(_on_progress)
            worker.finished.connect(_on_finished)
            worker.start()

        def _on_rag_delete_db():
            from PyQt6.QtWidgets import QMessageBox
            reply = QMessageBox.question(
                dlg,
                "Delete Vector Database",
                "Are you sure you want to delete the entire vector database?\nThis action cannot be undone.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
            _rag_dir = os.path.join(getattr(c, "base_path", _base_dir_rag), "appdata", "rag")
            try:
                import shutil
                _chroma_dir = os.path.join(_rag_dir, "chroma_db")
                _meta_file  = os.path.join(_rag_dir, "index_meta.json")
                deleted_any = False
                if os.path.exists(_chroma_dir):
                    shutil.rmtree(_chroma_dir)
                    deleted_any = True
                if os.path.exists(_meta_file):
                    os.remove(_meta_file)
                    deleted_any = True
                if deleted_any:
                    QMessageBox.information(dlg, "Done", "Vector database deleted.\n(Embedding models cache kept.)")
                else:
                    QMessageBox.information(dlg, "Done", "Nothing to delete — database was already empty.")
            except Exception as e:
                QMessageBox.critical(dlg, "Error", f"Failed to delete database:\n{e}")

        def _on_settings_agent_role_changed(idx):
            val = settings_agent_role_combo.currentText()
            _save_llama_key("agent_role", val)
            c.apply_agent_files(val, settings_skills_combo.currentText())

        def _on_settings_skills_changed(idx):
            val = settings_skills_combo.currentText()
            _save_llama_key("skills_set", val)
            c.apply_agent_files(settings_agent_role_combo.currentText(), val)

        def _on_ai_think_changed():
            _save_llama_key("ai_disable_thinking", ai_think_cb.isChecked())

        def _on_ai_fast_changed():
            _save_llama_key("ai_fast_answers", ai_fast_cb.isChecked())

        rag_model_combo.currentIndexChanged.connect(_on_rag_model_changed)
        rag_radio_braindump.toggled.connect(_on_rag_braindump_toggled)
        rag_radio_custom.toggled.connect(_on_rag_custom_toggled)
        rag_browse_btn.clicked.connect(_on_rag_browse)
        rag_auto_checkbox.stateChanged.connect(_on_rag_auto_index_changed)
        rag_reindex_btn.clicked.connect(_on_rag_reindex)
        rag_delete_btn.clicked.connect(_on_rag_delete_db)
        settings_agent_role_combo.currentIndexChanged.connect(_on_settings_agent_role_changed)
        settings_skills_combo.currentIndexChanged.connect(_on_settings_skills_changed)
        ai_think_cb.stateChanged.connect(_on_ai_think_changed)
        ai_fast_cb.stateChanged.connect(_on_ai_fast_changed)

        # ── API Providers group ───────────────────────────────────────────────
        import threading
        import urllib.request
        import urllib.error
        import stat

        _PROVIDER_TYPES    = ["ollama", "openai", "anthropic", "groq", "gemini"]
        _PROVIDER_BASE_URL = {
            "ollama":    "http://localhost:11434",
            "openai":    "https://api.openai.com/v1",
            "anthropic": "https://api.anthropic.com/v1",
            "groq":      "https://api.groq.com/openai/v1",
            "gemini":    "https://generativelanguage.googleapis.com/v1beta/openai",
            "custom":    "",
        }
        _base_dir_prov  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _api_keys_path  = os.path.join(
            getattr(c, "base_path", _base_dir_prov), "appdata", "api_keys.json"
        )
        _providers_cfg_key = "api_providers"

        # ── persistence helpers ───────────────────────────────────────────────
        def _load_api_keys():
            try:
                if os.path.exists(_api_keys_path):
                    with open(_api_keys_path, "r", encoding="utf-8") as f:
                        return json.load(f)
            except Exception:
                pass
            return {}

        def _save_api_key(profile_name, key):
            keys = _load_api_keys()
            if key:
                keys[profile_name] = key
            else:
                keys.pop(profile_name, None)
            try:
                with open(_api_keys_path, "w", encoding="utf-8") as f:
                    json.dump(keys, f, indent=2, ensure_ascii=False)
                os.chmod(_api_keys_path, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass

        def _remove_api_key(profile_name):
            _save_api_key(profile_name, "")

        def _rename_api_key(old_name, new_name):
            keys = _load_api_keys()
            if old_name in keys:
                keys[new_name] = keys.pop(old_name)
                try:
                    with open(_api_keys_path, "w", encoding="utf-8") as f:
                        json.dump(keys, f, indent=2, ensure_ascii=False)
                    os.chmod(_api_keys_path, stat.S_IRUSR | stat.S_IWUSR)
                except Exception:
                    pass

        def _load_providers_config():
            try:
                if os.path.exists(c.config_path):
                    with open(c.config_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                    return cfg.get(_providers_cfg_key, {})
            except Exception:
                pass
            return {}

        def _save_providers_to_config(profiles_list, active_name):
            try:
                cfg = {}
                if os.path.exists(c.config_path):
                    with open(c.config_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                cfg[_providers_cfg_key] = {
                    "active":   active_name,
                    "profiles": profiles_list,
                }
                with open(c.config_path, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
            except Exception:
                pass

        def _collect_profiles_from_table():
            profiles = []
            for r in range(providers_table.rowCount()):
                profiles.append({
                    "name":     providers_table.item(r, 0).text() if providers_table.item(r, 0) else "",
                    "provider": providers_table.item(r, 1).text() if providers_table.item(r, 1) else "",
                    "model":    providers_table.item(r, 2).text() if providers_table.item(r, 2) else "",
                    "url":      providers_table.item(r, 3).text() if providers_table.item(r, 3) else "",
                })
            return profiles

        def _persist():
            active = active_profile_combo.currentText()
            if active == "— none —":
                active = ""
            _save_providers_to_config(_collect_profiles_from_table(), active)
            # sync global combo in main window
            global_combo = c.widgets.get("global_active_profile_combo")
            reload_fn = c.widgets.get("global_active_profile_combo_reload")
            if global_combo is not None and reload_fn is not None:
                reload_fn(keep=active)

        # ── model fetch helper ────────────────────────────────────────────────
        def _fetch_provider_models(provider, url, key):
            """Fetch available models from provider API. Returns list[str] or raises."""
            base = (url.rstrip("/") if url else _PROVIDER_BASE_URL.get(provider, ""))

            if provider == "ollama":
                endpoint = f"{base}/api/tags"
                req = urllib.request.Request(endpoint)
                with urllib.request.urlopen(req, timeout=6) as resp:
                    data = json.loads(resp.read())
                models = data.get("models", [])
                return sorted(
                    m.get("name") or m.get("model", "") for m in models
                    if m.get("name") or m.get("model")
                )

            elif provider == "anthropic":
                endpoint = f"{base}/models"
                req = urllib.request.Request(endpoint, headers={
                    "x-api-key":         key,
                    "anthropic-version": "2023-06-01",
                    "Accept":            "application/json",
                    "User-Agent":        "Mozilla/5.0",
                })
                with urllib.request.urlopen(req, timeout=8) as resp:
                    data = json.loads(resp.read())
                return sorted(m["id"] for m in data.get("data", []) if "id" in m)

            else:
                # openai-compatible: openai / groq / custom
                endpoint = f"{base}/models"
                req = urllib.request.Request(endpoint, headers={
                    "Authorization":  f"Bearer {key}",
                    "Accept":         "application/json",
                    "User-Agent":     "Mozilla/5.0",
                })
                with urllib.request.urlopen(req, timeout=8) as resp:
                    data = json.loads(resp.read())
                return sorted(m["id"] for m in data.get("data", []) if "id" in m)

        # ── widgets ───────────────────────────────────────────────────────────
        grp_providers = QGroupBox("API Providers")
        grp_providers_layout = QVBoxLayout(grp_providers)
        grp_providers_layout.setContentsMargins(8, 8, 8, 8)
        grp_providers_layout.setSpacing(6)

        # Active profile row
        active_row = QHBoxLayout()
        active_row.addWidget(QLabel("Active profile:"))
        active_profile_combo = QComboBox()
        active_profile_combo.setMinimumWidth(160)
        active_profile_combo.addItem("— none —")
        active_row.addWidget(active_profile_combo)
        active_row.addStretch(1)
        grp_providers_layout.addLayout(active_row)
        c.register_widget("ai_active_profile_combo", active_profile_combo)

        # Profiles table
        providers_table = QTableWidget(0, 4)
        providers_table.setHorizontalHeaderLabels(["Name", "Provider", "Model", "URL"])
        providers_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        providers_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        providers_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        providers_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        providers_table.verticalHeader().setVisible(False)
        providers_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        providers_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        providers_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        providers_table.setMinimumHeight(120)
        providers_table.setMaximumHeight(180)
        grp_providers_layout.addWidget(providers_table)

        # Table action buttons
        tbl_btn_row = QHBoxLayout()
        btn_add_provider    = QPushButton("Add")
        btn_edit_provider   = QPushButton("Edit")
        btn_remove_provider = QPushButton("Remove")
        btn_edit_provider.setEnabled(False)
        btn_remove_provider.setEnabled(False)
        for _b in (btn_add_provider, btn_edit_provider, btn_remove_provider):
            _b.setFixedWidth(70)
            tbl_btn_row.addWidget(_b)
        tbl_btn_row.addStretch(1)
        grp_providers_layout.addLayout(tbl_btn_row)

        # ── Add/Edit profile dialog ───────────────────────────────────────────
        def _build_profile_dialog(title, defaults=None):
            d = defaults or {}
            pdlg = QDialog(dlg)
            pdlg.setWindowTitle(title)
            pdlg.setModal(True)
            pdlg.resize(420, 290)
            try:
                pdlg.setStyleSheet(c.messagebox_stylesheet)
            except Exception:
                pass
            form = QFormLayout(pdlg)
            form.setContentsMargins(14, 14, 14, 14)
            form.setSpacing(8)

            f_name     = QLineEdit(d.get("name", ""))
            f_name.setPlaceholderText("e.g. local-fast")
            f_provider = QComboBox()
            f_provider.addItems(_PROVIDER_TYPES)
            if d.get("provider") in _PROVIDER_TYPES:
                f_provider.setCurrentText(d["provider"])
            f_url = QLineEdit(d.get("url", ""))

            # Model: editable combo + Fetch button
            f_model = QComboBox()
            f_model.setEditable(True)
            f_model.setMinimumWidth(160)
            if d.get("model"):
                f_model.addItem(d["model"])
                f_model.setCurrentText(d["model"])
            f_model.lineEdit().setPlaceholderText("e.g. llama3.2 / gpt-4o")

            fetch_status = QLabel("")
            fetch_status.setStyleSheet("font-size: 11px; color: gray;")
            btn_fetch = QPushButton("Fetch models")
            btn_fetch.setFixedWidth(100)
            model_row = QHBoxLayout()
            model_row.addWidget(f_model, 1)
            model_row.addWidget(btn_fetch)

            f_key = QLineEdit(d.get("key", ""))
            f_key.setPlaceholderText("API key")
            f_key.setEchoMode(QLineEdit.EchoMode.Password)

            def _update_url_placeholder(idx=None):
                f_url.setPlaceholderText(
                    _PROVIDER_BASE_URL.get(f_provider.currentText(), "") or "Base URL"
                )
            f_provider.currentIndexChanged.connect(_update_url_placeholder)
            _update_url_placeholder()

            def _do_fetch():
                provider = f_provider.currentText()
                url      = f_url.text().strip()
                key      = f_key.text().strip()
                try:
                    models = _fetch_provider_models(provider, url, key)
                    return models, None
                except Exception as e:
                    return [], str(e)

            def _on_fetch():
                btn_fetch.setEnabled(False)
                fetch_status.setText("Fetching…")
                result = [None]

                def _worker():
                    result[0] = _do_fetch()

                def _done():
                    models, err = result[0]
                    btn_fetch.setEnabled(True)
                    if err:
                        fetch_status.setText(f"Error: {err[:60]}")
                        fetch_status.setStyleSheet("font-size: 11px; color: red;")
                    else:
                        current = f_model.currentText()
                        f_model.blockSignals(True)
                        f_model.clear()
                        f_model.addItems(models)
                        idx = f_model.findText(current)
                        f_model.setCurrentIndex(max(0, idx))
                        f_model.blockSignals(False)
                        fetch_status.setText(f"{len(models)} models found")
                        fetch_status.setStyleSheet("font-size: 11px; color: green;")

                t = threading.Thread(target=_worker, daemon=True)
                t.start()

                def _poll():
                    if t.is_alive():
                        QTimer.singleShot(150, _poll)
                    else:
                        _done()
                QTimer.singleShot(150, _poll)

            btn_fetch.clicked.connect(_on_fetch)

            form.addRow("Name:",     f_name)
            form.addRow("Provider:", f_provider)
            form.addRow("Base URL:", f_url)
            form.addRow("Model:",    model_row)
            form.addRow("",          fetch_status)
            form.addRow("API key:",  f_key)

            btn_row = QHBoxLayout()
            btn_ok     = QPushButton("OK")
            btn_cancel = QPushButton("Cancel")
            btn_ok.setFixedWidth(80)
            btn_cancel.setFixedWidth(80)
            btn_row.addStretch(1)
            btn_row.addWidget(btn_ok)
            btn_row.addWidget(btn_cancel)
            form.addRow(btn_row)

            btn_ok.clicked.connect(pdlg.accept)
            btn_cancel.clicked.connect(pdlg.reject)

            return pdlg, {
                "name":     f_name,
                "provider": f_provider,
                "model":    f_model,
                "url":      f_url,
                "key":      f_key,
            }

        # ── table helpers ─────────────────────────────────────────────────────
        def _table_row_to_dict(row):
            return {k: (providers_table.item(row, i).text()
                        if providers_table.item(row, i) else "")
                    for i, k in enumerate(["name", "provider", "model", "url"])}

        def _insert_table_row(row_idx, profile):
            providers_table.insertRow(row_idx)
            for col, key in enumerate(["name", "provider", "model", "url"]):
                item = QTableWidgetItem(profile.get(key, ""))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                providers_table.setItem(row_idx, col, item)

        def _refresh_active_combo(keep=None):
            keep = keep or active_profile_combo.currentText()
            active_profile_combo.blockSignals(True)
            active_profile_combo.clear()
            active_profile_combo.addItem("— none —")
            for r in range(providers_table.rowCount()):
                n = providers_table.item(r, 0)
                if n:
                    active_profile_combo.addItem(n.text())
            idx = active_profile_combo.findText(keep)
            active_profile_combo.setCurrentIndex(max(0, idx))
            active_profile_combo.blockSignals(False)

        # ── load saved profiles on open ───────────────────────────────────────
        _prov_cfg     = _load_providers_config()
        _saved_active = _prov_cfg.get("active", "")
        _api_keys     = _load_api_keys()
        for _p in _prov_cfg.get("profiles", []):
            _insert_table_row(providers_table.rowCount(), _p)
        _refresh_active_combo(keep=_saved_active)

        # ── action handlers ───────────────────────────────────────────────────
        def _on_table_selection_changed():
            has_sel = bool(providers_table.selectedItems())
            btn_edit_provider.setEnabled(has_sel)
            btn_remove_provider.setEnabled(has_sel)

        def _profile_from_fields(fields):
            model_text = fields["model"].currentText().strip()
            return {
                "name":     fields["name"].text().strip(),
                "provider": fields["provider"].currentText(),
                "model":    model_text,
                "url":      fields["url"].text().strip(),
            }

        def _on_add_provider():
            pdlg, fields = _build_profile_dialog("Add Provider Profile")
            if pdlg.exec() != QDialog.DialogCode.Accepted:
                return
            profile = _profile_from_fields(fields)
            if not profile["name"]:
                return
            _insert_table_row(providers_table.rowCount(), profile)
            _save_api_key(profile["name"], fields["key"].text())
            _refresh_active_combo()
            _persist()

        def _on_edit_provider():
            row = providers_table.currentRow()
            if row < 0:
                return
            old_name = providers_table.item(row, 0).text() if providers_table.item(row, 0) else ""
            current  = _table_row_to_dict(row)
            current["key"] = _load_api_keys().get(old_name, "")
            pdlg, fields = _build_profile_dialog("Edit Provider Profile", defaults=current)
            if pdlg.exec() != QDialog.DialogCode.Accepted:
                return
            profile = _profile_from_fields(fields)
            if not profile["name"]:
                return
            for col, k in enumerate(["name", "provider", "model", "url"]):
                item = QTableWidgetItem(profile[k])
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                providers_table.setItem(row, col, item)
            if profile["name"] != old_name:
                _rename_api_key(old_name, profile["name"])
            _save_api_key(profile["name"], fields["key"].text())
            _refresh_active_combo()
            _persist()

        def _on_remove_provider():
            row = providers_table.currentRow()
            if row < 0:
                return
            name = providers_table.item(row, 0).text() if providers_table.item(row, 0) else ""
            providers_table.removeRow(row)
            _remove_api_key(name)
            _on_table_selection_changed()
            _refresh_active_combo()
            _persist()

        def _on_active_changed():
            _persist()

        providers_table.itemSelectionChanged.connect(_on_table_selection_changed)
        active_profile_combo.currentIndexChanged.connect(_on_active_changed)
        btn_add_provider.clicked.connect(_on_add_provider)
        btn_edit_provider.clicked.connect(_on_edit_provider)
        btn_remove_provider.clicked.connect(_on_remove_provider)

        # ── Assemble dialog ───────────────────────────────────────────────────
        scroll_content = QWidget()
        scroll_content.setObjectName("ai_settings_scroll_content")
        scroll_content.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(4, 4, 4, 4)
        scroll_layout.setSpacing(8)
        scroll_layout.addWidget(grp_llm)
        scroll_layout.addWidget(grp_rag)
        scroll_layout.addWidget(grp_providers)
        scroll_layout.addStretch(1)

        scroll = QScrollArea(dlg)
        scroll.setObjectName("ai_settings_scroll")
        scroll.setWidgetResizable(True)
        scroll.setWidget(scroll_content)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        btn_close = QPushButton("Close", dlg)
        btn_close.clicked.connect(dlg.accept)
        btn_layout = QHBoxLayout()
        btn_layout.addStretch(1)
        btn_layout.addWidget(btn_close)

        main_layout = QVBoxLayout(dlg)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)
        main_layout.addWidget(scroll)
        main_layout.addLayout(btn_layout)

        try:
            c.register_widget("ai_settings_dialog", dlg)
            c.register_widget("ai_settings_llm_cli_edit",       llm_cli_edit)
            c.register_widget("ai_settings_logs_terminal_edit", logs_terminal_edit)
            c.register_widget("ai_settings_agent_role_combo",   settings_agent_role_combo)
            c.register_widget("ai_settings_skills_combo",       settings_skills_combo)
        except Exception:
            pass

    create_settings_dialog()
    create_ai_settings_dialog()
    create_about_qterm_dialog()
    create_about_qt_dialog()
    create_licenses_dialog()

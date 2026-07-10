from PyQt6.QtWidgets import (
    QPushButton, QDialog, QFormLayout, QHBoxLayout, QVBoxLayout,
    QLabel, QSpinBox, QDoubleSpinBox, QCheckBox, QLineEdit, QComboBox, QGroupBox, QScrollArea, QWidget,
    QRadioButton, QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView, QTextEdit,
    QListView, QListWidget, QListWidgetItem, QMessageBox, QTabWidget, QSizePolicy,
    QToolButton, QSlider, QPlainTextEdit,
)
from PyQt6.QtCore import Qt, QTimer, QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QAction, QIntValidator
import os
import json
import subprocess
import threading
import logging

from core.controller import controller_instance

logger = logging.getLogger(__name__)


class _ScrollableComboBox(QComboBox):
    """QComboBox popup capped at a fixed height with a real scrollbar (no arrow buttons)."""
    _MAX_H = 300

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setMaxVisibleItems(200)
        self._sb_qss = ""

    def setScrollBarStyleSheet(self, qss: str):
        self._sb_qss = qss

    def showPopup(self):
        super().showPopup()
        container = self.view().parent()
        if container and container is not self:
            view = self.view()
            for child in container.children():
                if isinstance(child, QWidget) and child is not view:
                    child.setMaximumHeight(0)
                    child.hide()
            view.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
            if self._sb_qss:
                view.verticalScrollBar().setStyleSheet(self._sb_qss)
            if container.height() > self._MAX_H:
                container.setFixedHeight(self._MAX_H)


c = controller_instance

def build_menu(main_window):

    menu_button = QPushButton("⋯", c.widgets["central_widget"])
    menu_button.setGeometry(10, 0, 40, 12)
    menu_button.setToolTip("Menu")
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
    edit_menu.addSeparator()
    tool_categories_action = QAction("Tool Categories", main_window)
    edit_menu.addAction(tool_categories_action)
    edit_menu.addSeparator()
    update_models_action = QAction("Update Model Database…", main_window)
    edit_menu.addAction(update_models_action)
    edit_menu.addSeparator()
    erase_data_action = QAction("Erase all data…", main_window)
    edit_menu.addAction(erase_data_action)

    def _open_erase_data():
        from gui.dialogs.erase_data_dialog import open_erase_data_dialog
        open_erase_data_dialog(c, main_window)
    erase_data_action.triggered.connect(_open_erase_data)

    c.register_widget("edit_menu", edit_menu)
    c.register_widget("command_palette_action", command_palette_action)
    c.register_widget("tool_categories_action", tool_categories_action)
    c.register_widget("update_models_action", update_models_action)
    c.register_widget("erase_data_action", erase_data_action)

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
    check_updates_action = QAction("Check for Updates", main_window)
    about_licenses_action = QAction("Licenses", main_window)
    health_check_action = QAction("Health Check", main_window)
    help_menu.addAction(user_guide_action)
    help_menu.addAction(manual_action)
    help_menu.addSeparator()
    help_menu.addAction(check_updates_action)
    help_menu.addAction(health_check_action)
    help_menu.addSeparator()
    help_menu.addAction(about_licenses_action)
    c.register_widget("user_guide_action", user_guide_action)
    c.register_widget("manual_action", manual_action)
    c.register_widget("check_updates_action", check_updates_action)
    c.register_widget("about_licenses_action", about_licenses_action)
    c.register_widget("health_check_action", health_check_action)

    def _run_health_check():
        """Run the pshealth dependency check in the active terminal."""
        term_tabs = c.widgets.get("terminal_tabs")
        if not term_tabs:
            return
        wrapper = term_tabs.widget(term_tabs.currentIndex())
        if wrapper is None:
            return
        term = c.wrapper_to_console.get(wrapper)
        if term is None:
            return
        try:
            term.sendText("pshealth\n")
        except Exception:
            logger.error("Failed to run health check in terminal", exc_info=True)

    health_check_action.triggered.connect(_run_health_check)

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

        fullwindow_checkbox = QCheckBox("Full window", grp_window)
        _fw_default = False
        try:
            if "window" in data:
                _fw_default = bool(data["window"].get("maximized", False))
            else:
                _fw_default = bool(getattr(c, "window_maximized", False))
        except Exception:
            pass
        fullwindow_checkbox.setChecked(_fw_default)
        form_window.addRow(fullwindow_checkbox)

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

        delete_logs_checkbox = QCheckBox("Clear DB history on exit", grp_behavior)
        delete_logs_checkbox.setChecked(c.delete_logs_at_close)
        form_behavior.addRow(delete_logs_checkbox)

        delete_notes_checkbox = QCheckBox("Clear notes on exit", grp_behavior)
        delete_notes_checkbox.setChecked(c.delete_notes_at_close)
        form_behavior.addRow(delete_notes_checkbox)

        disable_history_checkbox = QCheckBox("Disable DB history", grp_behavior)
        disable_history_checkbox.setChecked(getattr(c, "terminal_history_disabled", False))
        form_behavior.addRow(disable_history_checkbox)

        _HISTORY_MAX_DEFAULT = 10000
        _history_max_saved = getattr(c, "terminal_history_max_entries", _HISTORY_MAX_DEFAULT)
        history_max_spin = QSpinBox(grp_behavior)
        history_max_spin.setRange(100, 100000)
        history_max_spin.setValue(int(_history_max_saved))
        history_max_set_btn = QPushButton("Set", grp_behavior)
        history_max_set_btn.setFixedWidth(48)
        history_max_reset_btn = QPushButton("Default", grp_behavior)
        history_max_reset_btn.setFixedWidth(60)
        history_max_row = QHBoxLayout()
        history_max_row.addWidget(history_max_spin)
        history_max_row.addWidget(history_max_set_btn)
        history_max_row.addWidget(history_max_reset_btn)
        form_behavior.addRow("Max DB history entries:", history_max_row)

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
                logger.warning("failed to persist behavior setting to config", exc_info=True)

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

        def _on_history_max_set():
            from PyQt6.QtWidgets import QMessageBox
            new_val = history_max_spin.value()
            current = getattr(c, "terminal_history_max_entries", _HISTORY_MAX_DEFAULT)
            msg = QMessageBox(dlg)
            msg.setWindowTitle("Change DB history limit")
            msg.setText(
                f"Set max DB history entries to <b>{new_val}</b>?<br><br>"
                "Commands exceeding the limit will be deleted oldest-first.<br>"
                "This cannot be undone."
            )
            msg.setStandardButtons(
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel
            )
            msg.setDefaultButton(QMessageBox.StandardButton.Cancel)
            if msg.exec() != QMessageBox.StandardButton.Ok:
                history_max_spin.setValue(current)
                return
            c.terminal_history_max_entries = new_val
            _save_behavior_key("terminal_history_max_entries", new_val)
            try:
                db = c._get_term_db() if hasattr(c, "_get_term_db") else getattr(c, "_terminal_history_db", None)
                if db is not None:
                    db.trim_to_limit(new_val)
            except Exception:
                pass

        def _on_history_max_reset():
            history_max_spin.setValue(_HISTORY_MAX_DEFAULT)
            _on_history_max_set()

        def _save_window_settings():
            w = width_spin.value()
            h = height_spin.value()
            x = x_spin.value()
            y = y_spin.value()
            c.width = w
            c.height = h
            c.start_x = x
            c.start_y = y
            # Apply the new geometry to the live window immediately (same call the
            # main window uses at startup) so changes don't wait for a restart.
            # Skipped while maximized — Full window overrides explicit geometry.
            try:
                if not main_window.isMaximized():
                    main_window.setGeometry(x, y, w, h)
            except Exception:
                logger.debug("failed to apply window geometry live", exc_info=True)
            if not os.path.exists(c.config_path):
                return
            try:
                with open(c.config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                cfg.setdefault("window", {})["resolution"] = [w, h]
                cfg["window"]["start_screen"] = [x, y]
                with open(c.config_path, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
            except Exception:
                logger.warning("failed to persist window geometry to config", exc_info=True)

        def _on_lw_changed(state):
            c.lightweight_web_browser = lw_checkbox.isChecked()
            if not os.path.exists(c.config_path):
                return
            try:
                with open(c.config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                cfg.setdefault("performance", {})["lightweight_web_browser"] = c.lightweight_web_browser
                with open(c.config_path, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
            except Exception:
                logger.warning("failed to persist performance setting to config", exc_info=True)

        def _on_fullwindow_changed(state):
            checked = fullwindow_checkbox.isChecked()
            c.window_maximized = checked
            if checked:
                main_window.showMaximized()
            else:
                main_window.showNormal()
            if not os.path.exists(c.config_path):
                return
            try:
                with open(c.config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                cfg.setdefault("window", {})["maximized"] = checked
                with open(c.config_path, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
            except Exception:
                logger.warning("failed to persist maximized state to config", exc_info=True)

        width_spin.valueChanged.connect(lambda _: _save_window_settings())
        height_spin.valueChanged.connect(lambda _: _save_window_settings())
        x_spin.valueChanged.connect(lambda _: _save_window_settings())
        y_spin.valueChanged.connect(lambda _: _save_window_settings())
        fullwindow_checkbox.stateChanged.connect(_on_fullwindow_changed)
        lw_checkbox.stateChanged.connect(_on_lw_changed)
        save_sys_checkbox.stateChanged.connect(_on_save_sys_changed)
        delete_logs_checkbox.stateChanged.connect(_on_delete_logs_changed)
        delete_notes_checkbox.stateChanged.connect(_on_delete_notes_changed)
        restore_session_checkbox.stateChanged.connect(_on_restore_session_changed)
        disable_history_checkbox.stateChanged.connect(_on_disable_history_changed)
        history_max_set_btn.clicked.connect(_on_history_max_set)
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
            • <a href="https://pypi.org/project/jeepney/">jeepney 0.9.0</a> – MIT<br>
            • <a href="https://pypi.org/project/pymupdf/">PyMuPDF (fitz) 1.27.2.3</a> – AGPL v3<br>
            • <a href="https://pypi.org/project/mutagen/">mutagen 1.47.0</a> – GPL v2<br>
            • <a href="https://pypi.org/project/packaging/">packaging 25.0</a> – Apache 2.0 / BSD<br><br>

            <b>Voice &amp; Audio</b><br>
            • <a href="https://github.com/SYSTRAN/faster-whisper">faster-whisper 1.2.1</a> – MIT<br>
            • <a href="https://github.com/dscripka/openWakeWord">openwakeword 0.4.0</a> – Apache 2.0<br>
            • <a href="https://pypi.org/project/sounddevice/">sounddevice 0.5.5</a> – MIT<br>
            • <a href="https://pypi.org/project/scipy/">scipy 1.17.1</a> – BSD 3-Clause<br>
            • <a href="https://opennmt.net">ctranslate2 4.7.1</a> – MIT<br>
            • <a href="https://pypi.org/project/av/">av (PyAV) 17.0.1</a> – BSD 3-Clause<br>
            • <a href="https://scikit-learn.org">scikit-learn 1.8.0</a> – BSD 3-Clause<br>
            • <a href="https://github.com/huggingface/tokenizers">tokenizers 0.23.1</a> – Apache 2.0<br><br>

            <hr>
            <b>External Tools &amp; Resources</b><br>
            • <a href="https://exiftool.org">ExifTool</a> – Artistic / GPL<br><br>

            <hr>
            <b>Copyright &amp; Trademarks</b><br>
            • <b>Qt</b> — Copyright © The Qt Company Ltd. and other contributors.
              Used under GPL v3 via PyQt6. Qt and the Qt logo are trademarks of
              The Qt Company Ltd. — <a href="https://qt.io/licensing">qt.io/licensing</a><br>
            • <b>PyQt6</b> — Copyright © <a href="https://riverbankcomputing.com">Riverbank Computing Limited</a>.<br>
            • <b>QTermWidget</b> — Copyright © 2013–2026 LXQt Project —
              <a href="https://github.com/lxqt/qtermwidget">github.com/lxqt/qtermwidget</a><br><br>

            <hr>
            <div style="text-align: center; color: gray; font-size: 11px;">
                Full GPL / LGPL license texts are bundled in the <b>LICENSES/</b> folder of
                this project; per-dependency texts are available at the links above.
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

        from gui.builders.chat_panel_builder import DEFAULT_WEB_DOCKER_CMD

        llama_cfg = data.get("llama", {})
        llm_cli_default       = llama_cfg.get("llm_cli_path", "")
        logs_terminal_default = llama_cfg.get("logs_terminal_cmd", "")
        llm_web_chat_default  = llama_cfg.get("llm_web_chat_cmd", "") or DEFAULT_WEB_DOCKER_CMD

        dlg = QDialog(main_window)
        dlg.setWindowTitle("AI Settings")
        dlg.setModal(False)
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
                popup.setMinimumWidth(560)
                popup_layout = QVBoxLayout(popup)
                popup_layout.setContentsMargins(10, 10, 10, 10)
                popup_layout.setSpacing(6)
                # Multi-line editor — a single line is too cramped for long
                # values (e.g. the docker web-chat command).
                popup_edit = QPlainTextEdit(popup)
                popup_edit.setPlainText(e.text())
                popup_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
                popup_edit.setMinimumHeight(140)
                popup_layout.addWidget(popup_edit)
                popup_ok = QPushButton("OK", popup)
                popup_layout.addWidget(popup_ok, alignment=Qt.AlignmentFlag.AlignRight)

                def _confirm():
                    # Keep it a single logical line — the row edit is a QLineEdit
                    # and these values are one line. Soft-wrap adds no newlines;
                    # only neutralize any hard line breaks the user typed, so
                    # internal spaces (e.g. paths with spaces) are preserved.
                    val = popup_edit.toPlainText().replace("\r", " ").replace("\n", " ").strip()
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
                        logger.warning("failed to persist llama setting to config", exc_info=True)
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
        llm_web_chat_edit,  llm_web_chat_row  = _make_path_row(grp_llm, llm_web_chat_default,  "llm_web_chat_cmd")
        logs_terminal_edit, logs_terminal_row = _make_path_row(grp_llm, logs_terminal_default, "logs_terminal_cmd")

        form_llm.addRow("LLM CLI path:",       llm_cli_row)
        form_llm.addRow("LLM web chat cmd:",   llm_web_chat_row)
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
        form_llm.addRow("Skills & Agents:", settings_skills_combo)

        _goals_dir = os.path.join(c.base_path, "appdata", "agent_modes", "goals")
        _goals = []
        try:
            if os.path.isdir(_goals_dir):
                _goals = sorted(f for f in os.listdir(_goals_dir) if f.endswith(".md"))
        except Exception:
            pass
        settings_goal_combo = QComboBox(grp_llm)
        settings_goal_combo.addItem("none")
        settings_goal_combo.addItems(_goals)
        _saved_goal = llama_cfg.get("goal", "")
        if _saved_goal in _goals:
            settings_goal_combo.setCurrentText(_saved_goal)
        form_llm.addRow("Goal:", settings_goal_combo)

        clear_chat_history_checkbox = QCheckBox("Clear pschat history on exit", grp_llm)
        clear_chat_history_checkbox.setChecked(bool(llama_cfg.get("clear_chat_history_on_exit", False)))
        form_llm.addRow(clear_chat_history_checkbox)

        def _on_clear_chat_history_changed(state):
            val = clear_chat_history_checkbox.isChecked()
            _save_llama_key("clear_chat_history_on_exit", val)
            c.clear_chat_history_on_exit = val

        clear_chat_history_checkbox.stateChanged.connect(_on_clear_chat_history_changed)

        # ── ps* tools group ───────────────────────────────────────────────────
        grp_pstools = QGroupBox("ps* tools")
        form_pstools = QFormLayout(grp_pstools)
        form_pstools.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        psai_stats_checkbox = QCheckBox("Show inference stats after response", grp_pstools)
        psai_stats_checkbox.setChecked(bool(llama_cfg.get("psai_show_stats", True)))
        form_pstools.addRow(psai_stats_checkbox)

        def _on_psai_stats_changed(state):
            _save_llama_key("psai_show_stats", psai_stats_checkbox.isChecked())

        psai_stats_checkbox.stateChanged.connect(_on_psai_stats_changed)

        psai_querying_checkbox = QCheckBox("Show 'Querying model…' info line", grp_pstools)
        psai_querying_checkbox.setChecked(bool(llama_cfg.get("psai_show_querying", True)))
        form_pstools.addRow(psai_querying_checkbox)

        def _on_psai_querying_changed(state):
            _save_llama_key("psai_show_querying", psai_querying_checkbox.isChecked())

        psai_querying_checkbox.stateChanged.connect(_on_psai_querying_changed)

        psfix_popup_checkbox = QCheckBox("Auto-open psfix on command error", grp_pstools)
        psfix_popup_checkbox.setChecked(bool(llama_cfg.get("psfix_auto_open", True)))
        form_pstools.addRow(psfix_popup_checkbox)

        def _on_psfix_popup_changed(state):
            val = psfix_popup_checkbox.isChecked()
            _save_llama_key("psfix_auto_open", val)
            c.psfix_auto_open = val

        psfix_popup_checkbox.stateChanged.connect(_on_psfix_popup_changed)

        chat_history_spin = QSpinBox(grp_pstools)
        chat_history_spin.setRange(1, 999)
        chat_history_spin.setSingleStep(1)
        chat_history_spin.setValue(int(llama_cfg.get("chat_max_history", 20)))
        chat_history_spin.setMinimumWidth(80)

        chat_history_reset_btn = QPushButton("Default", grp_pstools)
        chat_history_reset_btn.setFixedWidth(60)
        chat_history_reset_btn.clicked.connect(lambda: chat_history_spin.setValue(20))

        chat_history_row = QHBoxLayout()
        chat_history_row.addWidget(chat_history_spin)
        chat_history_row.addWidget(chat_history_reset_btn)
        chat_history_row.addStretch(1)

        chat_history_hint = QLabel()
        chat_history_hint.setStyleSheet("color: gray; font-size: 11px;")

        def _update_chat_history_hint(value):
            chat_history_hint.setText(f"{value} prompts + {value} responses")

        _update_chat_history_hint(chat_history_spin.value())

        chat_history_col = QVBoxLayout()
        chat_history_col.setSpacing(2)
        chat_history_col.addLayout(chat_history_row)
        chat_history_col.addWidget(chat_history_hint)
        form_pstools.addRow("pschat history limit:", chat_history_col)

        def _on_chat_history_changed(value):
            _save_llama_key("chat_max_history", value)
            _update_chat_history_hint(value)

        chat_history_spin.valueChanged.connect(_on_chat_history_changed)

        term_history_spin = QSpinBox(grp_pstools)
        term_history_spin.setRange(1, 999)
        term_history_spin.setSingleStep(1)
        term_history_spin.setValue(int(llama_cfg.get("terminal_history_limit", 8)))
        term_history_spin.setMinimumWidth(80)

        term_history_reset_btn = QPushButton("Default", grp_pstools)
        term_history_reset_btn.setFixedWidth(60)
        term_history_reset_btn.clicked.connect(lambda: term_history_spin.setValue(8))

        broad_history_spin = QSpinBox(grp_pstools)
        broad_history_spin.setRange(0, 9999)
        broad_history_spin.setSingleStep(10)
        broad_history_spin.setValue(int(llama_cfg.get("terminal_history_broad_limit", 120)))
        broad_history_spin.setMinimumWidth(80)

        broad_history_reset_btn = QPushButton("Default", grp_pstools)
        broad_history_reset_btn.setFixedWidth(60)
        broad_history_reset_btn.clicked.connect(lambda: broad_history_spin.setValue(120))

        term_history_row = QHBoxLayout()
        term_history_row.addWidget(term_history_spin)
        term_history_row.addWidget(term_history_reset_btn)
        term_history_row.addSpacing(12)
        term_history_row.addWidget(broad_history_spin)
        term_history_row.addWidget(broad_history_reset_btn)
        term_history_row.addStretch(1)

        term_history_hint = QLabel()
        term_history_hint.setStyleSheet("color: gray; font-size: 11px;")

        def _update_term_history_hint():
            recent = term_history_spin.value()
            broad  = broad_history_spin.value()
            broad_str = f"  +  {broad} inputs with exit codes only" if broad > 0 else "  +  extended: disabled"
            term_history_hint.setText(f"{recent} inputs + {recent} outputs{broad_str}")

        _update_term_history_hint()

        term_history_col = QVBoxLayout()
        term_history_col.setSpacing(2)
        term_history_col.addLayout(term_history_row)
        term_history_col.addWidget(term_history_hint)
        form_pstools.addRow("psfix DB history limit:", term_history_col)

        def _on_term_history_changed(value):
            _save_llama_key("terminal_history_limit", value)
            _update_term_history_hint()

        def _on_broad_history_changed(value):
            _save_llama_key("terminal_history_broad_limit", value)
            _update_term_history_hint()

        term_history_spin.valueChanged.connect(_on_term_history_changed)
        broad_history_spin.valueChanged.connect(_on_broad_history_changed)

        # ── RAG group ─────────────────────────────────────────────────────────
        grp_rag = QGroupBox("RAG")
        grp_rag_layout = QVBoxLayout(grp_rag)
        grp_rag_layout.setSpacing(8)
        grp_rag_layout.setContentsMargins(6, 6, 6, 6)

        grp_kb  = QGroupBox("Knowledge")
        form_kb = QFormLayout(grp_kb)
        form_kb.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        grp_emb  = QGroupBox("Embedding")
        form_emb = QFormLayout(grp_emb)
        form_emb.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        grp_rnk  = QGroupBox("Re-ranking")
        form_rnk = QFormLayout(grp_rnk)
        form_rnk.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        grp_dl  = QGroupBox("Downloaded models")
        form_dl = QFormLayout(grp_dl)
        form_dl.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        grp_rag_layout.addWidget(grp_kb)
        grp_rag_layout.addWidget(grp_emb)
        grp_rag_layout.addWidget(grp_rnk)
        grp_rag_layout.addWidget(grp_dl)

        _rag_cfg = data.get("rag", {})
        _rag_mode = _rag_cfg.get("knowledge_base", "braindump")
        _rag_custom_path = _rag_cfg.get("custom_path", "")

        # (label, model_id) — model_id=None means a non-selectable group header
        _RAG_MODELS = [
            # ── English ──────────────────────────────────────────────────────
            ("English",                                    None),
            ("bge-small-en",                               "BAAI/bge-small-en"),
            ("bge-small-en-v1.5",                          "BAAI/bge-small-en-v1.5"),
            ("bge-base-en",                                "BAAI/bge-base-en"),
            ("bge-base-en-v1.5",                           "BAAI/bge-base-en-v1.5"),
            ("bge-large-en-v1.5",                          "BAAI/bge-large-en-v1.5"),
            ("all-MiniLM-L6-v2",                           "sentence-transformers/all-MiniLM-L6-v2"),
            ("gte-base",                                   "thenlper/gte-base"),
            ("gte-large",                                  "thenlper/gte-large"),
            ("mxbai-embed-large-v1",                       "mixedbread-ai/mxbai-embed-large-v1"),
            ("arctic-embed-xs",                            "snowflake/snowflake-arctic-embed-xs"),
            ("arctic-embed-s",                             "snowflake/snowflake-arctic-embed-s"),
            ("arctic-embed-m",                             "snowflake/snowflake-arctic-embed-m"),
            ("arctic-embed-m-long",                        "snowflake/snowflake-arctic-embed-m-long"),
            ("arctic-embed-l",                             "snowflake/snowflake-arctic-embed-l"),
            ("jina-embeddings-v2-base-en",                 "jinaai/jina-embeddings-v2-base-en"),
            # ── Multilingual ─────────────────────────────────────────────────
            ("Multilingual",                               None),
            ("nomic-embed-text-v1.5-Q",                    "nomic-ai/nomic-embed-text-v1.5-Q"),
            ("nomic-embed-text-v1.5",                      "nomic-ai/nomic-embed-text-v1.5"),
            ("nomic-embed-text-v1",                        "nomic-ai/nomic-embed-text-v1"),
            ("paraphrase-multilingual-MiniLM-L12-v2",      "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"),
            ("paraphrase-multilingual-mpnet-base-v2",      "sentence-transformers/paraphrase-multilingual-mpnet-base-v2"),
            ("multilingual-e5-large",                      "intfloat/multilingual-e5-large"),
            ("jina-embeddings-v3",                         "jinaai/jina-embeddings-v3"),
            # ── Language-specific ─────────────────────────────────────────────
            ("Language-specific",                          None),
            ("jina-embeddings-v2-base-de  [DE]",           "jinaai/jina-embeddings-v2-base-de"),
            ("jina-embeddings-v2-base-es  [ES]",           "jinaai/jina-embeddings-v2-base-es"),
            ("jina-embeddings-v2-base-zh  [ZH]",           "jinaai/jina-embeddings-v2-base-zh"),
            ("bge-small-zh-v1.5  [ZH]",                   "BAAI/bge-small-zh-v1.5"),
            # ── Code ──────────────────────────────────────────────────────────
            ("Code",                                       None),
            ("jina-embeddings-v2-base-code",               "jinaai/jina-embeddings-v2-base-code"),
            # ── Vision / Multimodal ───────────────────────────────────────────
            ("Vision / Multimodal",                        None),
            ("jina-clip-v1",                               "jinaai/jina-clip-v1"),
            ("clip-ViT-B-32-text",                         "Qdrant/clip-ViT-B-32-text"),
        ]
        _DEFAULT_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
        _saved_model   = _rag_cfg.get("embedding_model", _DEFAULT_MODEL)

        _EMB_TOOLTIPS = {
            "BAAI/bge-small-en":
                "Size: 130MB | Dim: 384 | English\nRetrieval, semantic search. Older version — v1.5 recommended.",
            "BAAI/bge-small-en-v1.5":
                "Size: 67MB | Dim: 384 | English\nRetrieval, semantic search. Lightest BGE model.",
            "BAAI/bge-base-en":
                "Size: 420MB | Dim: 768 | English\nRetrieval, semantic similarity.",
            "BAAI/bge-base-en-v1.5":
                "Size: 210MB | Dim: 768 | English\nRetrieval, MTEB 63.55. Good size/quality balance.",
            "BAAI/bge-large-en-v1.5":
                "Size: 1.2GB | Dim: 1024 | English\nBest English BGE. MTEB 64.23. Recommended for RAG.",
            "sentence-transformers/all-MiniLM-L6-v2":
                "Size: 90MB | Dim: 384 | English\nSemantic search, clustering. Most popular (254M+ downloads/month).",
            "thenlper/gte-base":
                "Size: 440MB | Dim: 768 | English\nRetrieval, similarity, reranking. Max 512 tokens.",
            "thenlper/gte-large":
                "Size: 1.2GB | Dim: 1024 | English\nRetrieval, similarity, reranking. Max 512 tokens.",
            "mixedbread-ai/mxbai-embed-large-v1":
                "Size: 640MB | Dim: 1024 | English\nSemantic search. MTEB 64.68 (SOTA BERT-large).\nSupports Matryoshka and binary quantization.",
            "snowflake/snowflake-arctic-embed-xs":
                "Size: 90MB | Dim: 384 | English\nRetrieval with strict latency constraints. 22M params.",
            "snowflake/snowflake-arctic-embed-s":
                "Size: 130MB | Dim: 384 | English\nRetrieval, small and fast.",
            "snowflake/snowflake-arctic-embed-m":
                "Size: 430MB | Dim: 768 | English\nRetrieval, good quality/speed tradeoff.",
            "snowflake/snowflake-arctic-embed-m-long":
                "Size: 540MB | Dim: 768 | English\nLong document retrieval. Up to 2048 tokens (8192 with RPE).",
            "snowflake/snowflake-arctic-embed-l":
                "Size: 1.0GB | Dim: 1024 | English\nHigh quality retrieval.",
            "jinaai/jina-embeddings-v2-base-en":
                "Size: 520MB | Dim: 768 | English\nLong context (8k tokens), RAG, semantic search. 137M params.",
            "nomic-ai/nomic-embed-text-v1.5-Q":
                "Size: 130MB | Dim: 768 | English (primary)\nMulti-task, 8192 tokens. Matryoshka resizable embeddings. Quantized.",
            "nomic-ai/nomic-embed-text-v1.5":
                "Size: 520MB | Dim: 768 | English (primary)\nMulti-task, 8192 tokens. Matryoshka resizable embeddings. Full precision.",
            "nomic-ai/nomic-embed-text-v1":
                "Size: 520MB | Dim: 768 | English (primary)\nOlder version — v1.5 recommended.",
            "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2":
                "Size: 220MB | Dim: 384 | 50+ languages\nSemantic similarity, clustering. Lightweight multilingual.",
            "sentence-transformers/paraphrase-multilingual-mpnet-base-v2":
                "Size: 1.0GB | Dim: 768 | 50+ languages\nSemantic similarity, clustering. Higher quality than MiniLM.",
            "intfloat/multilingual-e5-large":
                "Size: 2.24GB | Dim: 1024 | 94+ languages\nRetrieval, bitext mining. Requires 'query:'/'passage:' prefixes.",
            "jinaai/jina-embeddings-v3":
                "Size: 2.29GB | Dim: 1024 | Multilingual\nLargest Jina model. Long context, high quality.",
            "jinaai/jina-embeddings-v2-base-de":
                "Size: 320MB | Dim: 768 | German + English\nLong context (8k tokens), semantic search.",
            "jinaai/jina-embeddings-v2-base-es":
                "Size: 640MB | Dim: 768 | Spanish + English\nLong context (8k tokens), semantic search.",
            "jinaai/jina-embeddings-v2-base-zh":
                "Size: 640MB | Dim: 768 | Chinese + English\nLong context (8k tokens), semantic search.",
            "BAAI/bge-small-zh-v1.5":
                "Size: 90MB | Dim: 512 | Chinese\nRetrieval, lightweight Chinese model.",
            "jinaai/jina-embeddings-v2-base-code":
                "Size: 640MB | Dim: 768 | English + 30 programming languages\nCode search, technical Q&A. 8k tokens. Trained on 150M+ coding QA pairs.",
            "jinaai/jina-clip-v1":
                "Size: 550MB | Dim: 768 | English\nText + Image retrieval. Combines CLIP with text embeddings. SOTA cross-modal.",
            "Qdrant/clip-ViT-B-32-text":
                "Size: 250MB | Dim: 512 | Multilingual (CLIP-based)\nText-only ONNX port of clip-ViT-B-32. Similarity, classification.",
        }

        _RNK_TOOLTIPS = {
            "Xenova/ms-marco-MiniLM-L-6-v2":
                "Size: 80MB | English\nFast reranking, lightweight. Good for everyday use.",
            "Xenova/ms-marco-MiniLM-L-12-v2":
                "Size: 120MB | English\nBetter quality than L-6 at moderate speed cost.",
            "BAAI/bge-reranker-base":
                "Size: 1.04GB | Chinese + English\nCross-encoder, accurate but slower. 300M params.",
            "jinaai/jina-reranker-v1-tiny-en":
                "Size: 130MB | English\nFastest Jina reranker. 8k context.",
            "jinaai/jina-reranker-v1-turbo-en":
                "Size: 150MB | English\nFast, 8k context, knowledge-distilled. NDCG@10: 49.60.",
            "jinaai/jina-reranker-v2-base-multilingual":
                "Size: 1.11GB | 26+ languages\nMultilingual reranking. Sliding window for long inputs. Flash Attention.",
        }

        _base_dir_rag = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _rag_models_cache_dir = os.path.join(
            getattr(c, "base_path", _base_dir_rag), "appdata", "rag", "models"
        )

        def _build_cache_map(list_fn):
            result = {}
            try:
                for m in list_fn():
                    mid    = m.get("model", "")
                    hf_src = m.get("sources", {}).get("hf", "")
                    if mid and hf_src and "/" in hf_src:
                        org, repo = hf_src.split("/", 1)
                        result[mid] = f"models--{org}--{repo}"
            except Exception:
                pass
            return result

        def _is_cached(model_id, cache_map):
            key = cache_map.get(model_id)
            return bool(key and os.path.isdir(os.path.join(_rag_models_cache_dir, key)))

        def _cache_dir_for(model_id, cache_map):
            key = cache_map.get(model_id)
            if not key:
                return None
            full = os.path.join(_rag_models_cache_dir, key)
            return full if os.path.isdir(full) else None

        def _cache_dir_path(model_id, cache_map):
            """Like _cache_dir_for but without existence check (for post-delete use)."""
            key = cache_map.get(model_id)
            return os.path.join(_rag_models_cache_dir, key) if key else None

        def _dir_size_mb(path):
            try:
                total = sum(
                    os.path.getsize(os.path.join(root, f))
                    for root, _, files in os.walk(path)
                    for f in files
                )
                return total / (1024 * 1024)
            except Exception:
                return 0.0

        try:
            from fastembed import TextEmbedding as _TE
            from fastembed.rerank.cross_encoder import TextCrossEncoder as _TCE
            _emb_cache_map = _build_cache_map(_TE.list_supported_models)
            _rnk_cache_map = _build_cache_map(_TCE.list_supported_models)
        except Exception:
            _emb_cache_map = {}
            _rnk_cache_map = {}

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
        form_kb.addRow("Knowledge base:", rag_radio_row)

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
        form_kb.addRow("Path:", rag_path_row)

        # ── Embedding model ────────────────────────────────────────────────────
        from PyQt6.QtGui import QStandardItem
        rag_model_combo = _ScrollableComboBox(grp_rag)
        _emb_bg = c.actual_theme.get("background", {})
        rag_model_combo.setScrollBarStyleSheet(f"""
            QScrollBar:vertical {{
                background: transparent;
                width: 8px;
                margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background: {_emb_bg.get("scroll", "#555555")};
                border-radius: 4px;
                min-height: 20px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {_emb_bg.get("scroll_handle", "#707070")};
            }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{
                height: 0; background: none; border: none;
            }}
            QScrollBar::add-page:vertical,
            QScrollBar::sub-page:vertical {{
                background: {_emb_bg.get("scroll_area", "#1E1F22")};
            }}
        """)
        for _label, _val in _RAG_MODELS:
            if _val is None:
                _hdr = QStandardItem(f"  ── {_label} ──")
                _hdr.setEnabled(False)
                _hdr.setData(None, Qt.ItemDataRole.UserRole)
                rag_model_combo.model().appendRow(_hdr)
            else:
                _sfx = "  ✓ downloaded" if _is_cached(_val, _emb_cache_map) else ""
                rag_model_combo.addItem("    " + _label + _sfx, _val)
                _tip = _EMB_TOOLTIPS.get(_val)
                if _tip:
                    rag_model_combo.setItemData(rag_model_combo.count() - 1, _tip, Qt.ItemDataRole.ToolTipRole)
        _saved_idx = next(
            (i for i in range(rag_model_combo.count())
             if rag_model_combo.itemData(i) == _saved_model), 0
        )
        rag_model_combo.setCurrentIndex(_saved_idx)
        form_emb.addRow("Embedding model:", rag_model_combo)

        _emb_info_btn = QToolButton(grp_emb)
        _emb_info_btn.setText("ℹ")
        _emb_info_btn.setAutoRaise(True)
        _emb_info_btn.setToolTip("⚠ Warning: selecting a model that does not support your language will result in inaccurate or no search results.")

        def _show_emb_info():
            msg = QMessageBox(dlg)
            msg.setWindowTitle("Choosing an Embedding Model")
            msg.setText(
                "<b>Things to consider when selecting an embedding model</b>"
                "<hr>"
                "<b>Language support</b><br>"
                "Ensure the model covers the language(s) of your documents. "
                "A model that does not support your document language will produce "
                "poor or no matches during search."
                "<br><br>"
                "<b>Use case</b><br>"
                "Models differ in what they are optimised for: semantic search, retrieval, "
                "clustering, or cross-lingual tasks. Hover over a model name in the list "
                "to see its intended use case and supported languages."
                "<br><br>"
                "<b>Memory footprint</b><br>"
                "Larger models generally produce better results but consume significantly "
                "more RAM during indexing. Consider your available system resources when "
                "choosing between a lightweight and a high-accuracy model."
            )
            msg.setStyleSheet(c.messagebox_stylesheet)
            msg.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg.exec()

        _emb_info_btn.clicked.connect(_show_emb_info)
        _emb_info_row = QHBoxLayout()
        _emb_info_row.addWidget(_emb_info_btn)
        _emb_info_row.addStretch(1)
        form_emb.addRow(_emb_info_row)

        # ── Re-ranking ─────────────────────────────────────────────────────────
        _rag_rerank = _rag_cfg.get("rerank", False)
        rag_rerank_checkbox = QCheckBox(
            "Enable re-ranking  (better results, ~1–2 s extra per query)", grp_rag
        )
        rag_rerank_checkbox.setChecked(bool(_rag_rerank))
        form_rnk.addRow("Enable:", rag_rerank_checkbox)

        _RERANK_MODELS = [
            ("ms-marco-MiniLM-L-6-v2",            "Xenova/ms-marco-MiniLM-L-6-v2"),
            ("ms-marco-MiniLM-L-12-v2",           "Xenova/ms-marco-MiniLM-L-12-v2"),
            ("jina-reranker-v1-tiny-en",           "jinaai/jina-reranker-v1-tiny-en"),
            ("jina-reranker-v1-turbo-en",          "jinaai/jina-reranker-v1-turbo-en"),
            ("bge-reranker-base",                  "BAAI/bge-reranker-base"),
            ("jina-reranker-v2-base-multilingual", "jinaai/jina-reranker-v2-base-multilingual"),
        ]
        _DEFAULT_RERANK_MODEL = "Xenova/ms-marco-MiniLM-L-6-v2"
        _saved_rerank_model   = _rag_cfg.get("rerank_model", _DEFAULT_RERANK_MODEL)

        rag_rerank_combo = _ScrollableComboBox(grp_rag)
        rag_rerank_combo.setScrollBarStyleSheet(f"""
            QScrollBar:vertical {{
                background: transparent;
                width: 8px;
                margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background: {_emb_bg.get("scroll", "#555555")};
                border-radius: 4px;
                min-height: 20px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {_emb_bg.get("scroll_handle", "#707070")};
            }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{
                height: 0; background: none; border: none;
            }}
            QScrollBar::add-page:vertical,
            QScrollBar::sub-page:vertical {{
                background: {_emb_bg.get("scroll_area", "#1E1F22")};
            }}
        """)
        for _label, _val in _RERANK_MODELS:
            _sfx = "  ✓ downloaded" if _is_cached(_val, _rnk_cache_map) else ""
            rag_rerank_combo.addItem(_label + _sfx, _val)
            _tip = _RNK_TOOLTIPS.get(_val)
            if _tip:
                rag_rerank_combo.setItemData(rag_rerank_combo.count() - 1, _tip, Qt.ItemDataRole.ToolTipRole)
        _saved_rerank_idx = next(
            (i for i in range(rag_rerank_combo.count())
             if rag_rerank_combo.itemData(i) == _saved_rerank_model), 0
        )
        rag_rerank_combo.setCurrentIndex(_saved_rerank_idx)
        rag_rerank_combo.setEnabled(bool(_rag_rerank))
        form_rnk.addRow("Rerank model:", rag_rerank_combo)

        _rnk_info_btn = QToolButton(grp_rnk)
        _rnk_info_btn.setText("ℹ")
        _rnk_info_btn.setAutoRaise(True)
        _rnk_info_btn.setToolTip("⚠ Warning: selecting a reranker that does not support your language will result in inaccurate or no search results.")

        def _show_rnk_info():
            msg = QMessageBox(dlg)
            msg.setWindowTitle("Choosing a Rerank Model")
            msg.setText(
                "<b>Things to consider when selecting a reranker</b>"
                "<hr>"
                "<b>Language support</b><br>"
                "Ensure the reranker covers the language(s) of your documents. "
                "Most rerankers are optimised for English only. Hover over a model "
                "name in the list to see its supported languages."
                "<br><br>"
                "<b>Use case</b><br>"
                "Rerankers re-score retrieval results for higher precision. "
                "Lightweight models offer lower latency, while larger models may produce "
                "more accurate rankings at the cost of additional processing time."
                "<br><br>"
                "<b>Memory footprint</b><br>"
                "Rerankers are loaded on every query when re-ranking is enabled. "
                "Larger models will increase per-query RAM usage and response time."
            )
            msg.setStyleSheet(c.messagebox_stylesheet)
            msg.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg.exec()

        _rnk_info_btn.clicked.connect(_show_rnk_info)
        _rnk_info_row = QHBoxLayout()
        _rnk_info_row.addWidget(_rnk_info_btn)
        _rnk_info_row.addStretch(1)
        form_rnk.addRow(_rnk_info_row)

        # ── Downloaded models ──────────────────────────────────────────────────
        rag_dl_list = QListWidget(grp_rag)
        rag_dl_list.setFixedHeight(5 * 24)
        rag_dl_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        rag_dl_list.setAlternatingRowColors(False)

        rag_dl_remove_btn = QPushButton("🗑  Remove selected", grp_rag)
        rag_dl_remove_btn.setEnabled(False)

        rag_dl_col = QVBoxLayout()
        rag_dl_col.setSpacing(4)
        rag_dl_col.addWidget(rag_dl_list)
        rag_dl_col.addWidget(rag_dl_remove_btn)
        form_dl.addRow("Models:", rag_dl_col)

        def _dl_list_populate():
            rag_dl_list.clear()
            _seen_dirs = set()
            for _label, _val in _RAG_MODELS:
                if _is_cached(_val, _emb_cache_map):
                    _d = _cache_dir_for(_val, _emb_cache_map)
                    if _d in _seen_dirs:
                        continue
                    _seen_dirs.add(_d)
                    item = QListWidgetItem(f"[Embed]   {_label}")
                    item.setData(Qt.ItemDataRole.UserRole, ("embed", _val))
                    rag_dl_list.addItem(item)
            for _label, _val in _RERANK_MODELS:
                if _is_cached(_val, _rnk_cache_map):
                    _d = _cache_dir_for(_val, _rnk_cache_map)
                    if _d in _seen_dirs:
                        continue
                    _seen_dirs.add(_d)
                    item = QListWidgetItem(f"[Rerank]  {_label}")
                    item.setData(Qt.ItemDataRole.UserRole, ("rerank", _val))
                    rag_dl_list.addItem(item)
            rag_dl_remove_btn.setEnabled(False)

        _dl_list_populate()

        def _dl_selection_changed():
            rag_dl_remove_btn.setEnabled(rag_dl_list.currentRow() >= 0)

        def _dl_remove():
            item = rag_dl_list.currentItem()
            if not item:
                return
            kind, model_id = item.data(Qt.ItemDataRole.UserRole)
            cache_map = _emb_cache_map if kind == "embed" else _rnk_cache_map
            cache_path = _cache_dir_for(model_id, cache_map)
            if not cache_path:
                return
            from PyQt6.QtWidgets import QMessageBox
            import shutil
            if kind == "embed" and model_id == (rag_model_combo.currentData() or ""):
                QMessageBox.warning(
                    dlg, "Cannot delete",
                    "This model is currently selected as the active Embedding model.\n\n"
                    "Select a different model first, then delete this one."
                )
                return
            reply = QMessageBox.question(
                dlg, "Delete model cache",
                f"Delete cached files for:\n{item.text()}\n\nFolder:\n{cache_path}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
            try:
                shutil.rmtree(cache_path)
            except Exception as e:
                QMessageBox.warning(dlg, "Error", f"Failed to delete:\n{e}")
                return
            # Remove ✓ downloaded from all combo items sharing the same cache dir
            for i in range(rag_model_combo.count()):
                _mid = rag_model_combo.itemData(i) or ""
                if _cache_dir_path(_mid, _emb_cache_map) == cache_path:
                    rag_model_combo.setItemText(i, rag_model_combo.itemText(i).replace("  ✓ downloaded", ""))
            for i in range(rag_rerank_combo.count()):
                _mid = rag_rerank_combo.itemData(i) or ""
                if _cache_dir_path(_mid, _rnk_cache_map) == cache_path:
                    rag_rerank_combo.setItemText(i, rag_rerank_combo.itemText(i).replace("  ✓ downloaded", ""))
            _dl_list_populate()

        def _dl_show_info(item):
            if not item:
                return
            kind, model_id = item.data(Qt.ItemDataRole.UserRole)
            tips = _EMB_TOOLTIPS if kind == "embed" else _RNK_TOOLTIPS
            tip = tips.get(model_id, "")
            label = item.text().split(None, 1)[1].strip() if item.text() else model_id
            msg = QMessageBox(dlg)
            msg.setWindowTitle(label)
            msg.setText(f"<b>{label}</b>")
            msg.setInformativeText(tip if tip else model_id)
            msg.setStyleSheet(c.messagebox_stylesheet)
            msg.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg.exec()

        rag_dl_list.currentRowChanged.connect(_dl_selection_changed)
        rag_dl_list.itemDoubleClicked.connect(_dl_show_info)
        rag_dl_remove_btn.clicked.connect(_dl_remove)

        # ── Index extensions ───────────────────────────────────────────────────
        from core.rag.chunker import ALL_EXTENSIONS, DEFAULT_EXTENSIONS
        _saved_exts = set(_rag_cfg.get("index_extensions", list(DEFAULT_EXTENSIONS)))

        _EXT_GROUPS = [
            ("Documents", ["pdf", "txt", "md", "rst"]),
            ("Data",      ["csv", "json", "xml", "yaml", "yml", "toml"]),
            ("Code",      ["py", "js", "ts", "sh", "html"]),
        ]

        def _ext_summary(exts: set) -> str:
            active = [e for grp in _EXT_GROUPS for e in grp[1] if e in exts and e in ALL_EXTENSIONS]
            return ", ".join(f".{e}" for e in active) if active else "none"

        ext_row_widget = QWidget(grp_rag)
        ext_row = QHBoxLayout(ext_row_widget)
        ext_row.setContentsMargins(0, 0, 0, 0)
        ext_row.setSpacing(6)
        ext_summary_lbl = QLabel(_ext_summary(_saved_exts), ext_row_widget)
        ext_summary_lbl.setStyleSheet("font-size: 11px;")
        ext_configure_btn = QPushButton("Configure…", ext_row_widget)
        ext_configure_btn.setFixedWidth(90)
        ext_row.addWidget(ext_summary_lbl)
        ext_row.addStretch(1)
        ext_row.addWidget(ext_configure_btn)
        form_kb.addRow("Index\nextensions:", ext_row_widget)

        def _open_ext_dialog():
            popup = QDialog(dlg)
            popup.setWindowTitle("Index extensions")
            popup.setModal(True)
            popup_layout = QVBoxLayout(popup)
            popup_layout.setSpacing(10)
            popup_layout.setContentsMargins(16, 12, 16, 12)

            _ext_checkboxes: dict[str, QCheckBox] = {}
            current_exts = set(_rag_cfg.get("index_extensions", list(DEFAULT_EXTENSIONS)))

            for _group_label, _group_exts in _EXT_GROUPS:
                grp = QGroupBox(_group_label, popup)
                grp_layout = QHBoxLayout(grp)
                grp_layout.setSpacing(8)
                for _ext in _group_exts:
                    if _ext not in ALL_EXTENSIONS:
                        continue
                    cb = QCheckBox(f".{_ext}", grp)
                    cb.setChecked(_ext in current_exts)
                    _ext_checkboxes[_ext] = cb
                    grp_layout.addWidget(cb)
                grp_layout.addStretch(1)
                popup_layout.addWidget(grp)

            close_btn = QPushButton("Close", popup)
            close_btn.setFixedWidth(80)
            close_btn.clicked.connect(popup.accept)
            btn_row = QHBoxLayout()
            btn_row.addStretch(1)
            btn_row.addWidget(close_btn)
            popup_layout.addLayout(btn_row)

            def _on_ext_changed():
                chosen = [e for e, cb in _ext_checkboxes.items() if cb.isChecked()]
                _save_rag_key("index_extensions", chosen)
                _rag_cfg["index_extensions"] = chosen
                ext_summary_lbl.setText(_ext_summary(set(chosen)))

                # Remove indexed files whose extension is no longer active
                chosen_set = set(chosen)
                meta = _load_file_meta()
                changed = False
                for abs_path in list(meta.keys()):
                    ext = os.path.splitext(abs_path)[1].lstrip(".").lower()
                    if ext and ext not in chosen_set:
                        chunk_ids = meta[abs_path].get("chunk_ids", [])
                        _delete_chunks_from_db(chunk_ids)
                        del meta[abs_path]
                        changed = True
                if changed:
                    _save_file_meta(meta)

                _populate_files_list()

            for _cb in _ext_checkboxes.values():
                _cb.stateChanged.connect(_on_ext_changed)

            popup.setStyleSheet(c.messagebox_stylesheet)
            popup.exec()

        ext_configure_btn.clicked.connect(_open_ext_dialog)

        # ── Indexing ───────────────────────────────────────────────────────────
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
        form_kb.addRow("Indexing:", rag_index_row)

        # ── Status ─────────────────────────────────────────────────────────────
        rag_status_label = QLabel("", grp_rag)
        rag_status_label.setStyleSheet("color: gray; font-size: 11px;")
        rag_status_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse |
            Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        rag_status_label.setWordWrap(True)
        form_kb.addRow("Status:", rag_status_label)

        # ── Indexed files manager ──────────────────────────────────────────────
        _base_dir_files = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _rag_dir_files  = os.path.join(getattr(c, "base_path", _base_dir_files), "appdata", "rag")
        _excl_path      = os.path.join(_rag_dir_files, "excluded_files.json")
        _meta_path_ui   = os.path.join(_rag_dir_files, "index_meta.json")

        from core.rag.indexer import load_exclusions, save_exclusions

        _STATUS_INDEXED  = "✓ indexed"
        _STATUS_PENDING  = "⟳ pending"
        _STATUS_EXCLUDED = "✗ excluded"

        files_list = QListWidget(grp_rag)
        files_list.setFixedHeight(6 * 24)
        files_list.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        files_list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        form_kb.addRow("Indexed\nfiles:", files_list)

        memory_list = QListWidget(grp_rag)
        memory_list.setFixedHeight(6 * 24)
        memory_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        memory_list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        mem_del_btn = QPushButton("Delete selected")
        mem_del_btn.setEnabled(False)
        mem_clear_btn = QPushButton("Delete all snippets")

        mem_btn_layout = QHBoxLayout()
        mem_btn_layout.setContentsMargins(0, 0, 0, 0)
        mem_btn_layout.setSpacing(4)
        mem_btn_layout.addWidget(mem_del_btn)
        mem_btn_layout.addWidget(mem_clear_btn)

        mem_snippet_layout = QVBoxLayout()
        mem_snippet_layout.setContentsMargins(0, 0, 0, 0)
        mem_snippet_layout.setSpacing(2)
        mem_snippet_layout.addWidget(memory_list)
        mem_snippet_layout.addLayout(mem_btn_layout)
        mem_snippet_widget = QWidget(grp_rag)
        mem_snippet_widget.setLayout(mem_snippet_layout)
        form_kb.addRow("Terminal\nsnippets:", mem_snippet_widget)

        def _mem_populate():
            memory_list.clear()
            mem_del_btn.setEnabled(False)
            try:
                from core.rag.indexer import get_memory_entries
                entries = get_memory_entries(getattr(c, "base_path", _base_dir_rag))
            except Exception:
                entries = []
            for entry in entries:
                preview = entry["text"][:40].replace("\n", " ")
                if len(entry["text"]) > 40:
                    preview += "…"
                item = QListWidgetItem(preview)
                item.setData(Qt.ItemDataRole.UserRole, entry["id"])
                item.setToolTip(entry["text"][:800])
                memory_list.addItem(item)

        _mem_populate()

        def _on_mem_selection_changed():
            mem_del_btn.setEnabled(bool(memory_list.selectedItems()))

        def _on_mem_delete():
            item = memory_list.currentItem()
            if item is None:
                return
            from PyQt6.QtWidgets import QMessageBox
            reply = QMessageBox.question(
                grp_rag, "Delete snippet",
                "Are you sure you want to delete the selected snippet?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
            entry_id = item.data(Qt.ItemDataRole.UserRole)
            try:
                from core.rag.indexer import delete_memory_entry
                delete_memory_entry(entry_id, getattr(c, "base_path", _base_dir_rag))
            except Exception:
                pass
            _mem_populate()

        def _on_mem_clear_all():
            from PyQt6.QtWidgets import QMessageBox
            reply = QMessageBox.question(
                grp_rag, "Clear all snippets",
                "Are you sure you want to delete all terminal snippets?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
            try:
                from core.rag.indexer import get_memory_entries, delete_memory_entry
                base = getattr(c, "base_path", _base_dir_rag)
                for entry in get_memory_entries(base):
                    delete_memory_entry(entry["id"], base)
            except Exception:
                pass
            _mem_populate()

        memory_list.itemSelectionChanged.connect(_on_mem_selection_changed)
        mem_del_btn.clicked.connect(_on_mem_delete)
        mem_clear_btn.clicked.connect(_on_mem_clear_all)

        def _load_file_meta() -> dict:
            if os.path.exists(_meta_path_ui):
                try:
                    with open(_meta_path_ui, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    logger.debug("failed to read RAG file-meta, using empty", exc_info=True)
            return {}

        def _delete_chunks_from_db(chunk_ids: list) -> None:
            if not chunk_ids:
                return
            try:
                import chromadb
                from chromadb.api.client import SharedSystemClient
                try:
                    SharedSystemClient.clear_system_cache()
                except Exception:
                    pass
                _db_path = os.path.join(_rag_dir_files, "chroma_db")
                client = chromadb.PersistentClient(path=_db_path)
                col = client.get_or_create_collection("rag_kb", metadata={"hnsw:space": "cosine"})
                col.delete(ids=chunk_ids)
            except Exception:
                pass

        def _save_file_meta(meta: dict) -> None:
            try:
                with open(_meta_path_ui, "w", encoding="utf-8") as f:
                    json.dump(meta, f, indent=2, ensure_ascii=False)
            except Exception:
                logger.warning("failed to persist RAG file-meta", exc_info=True)

        def _kb_path_now() -> str:
            kb = rag_path_edit.text().strip()
            return kb if kb and os.path.isdir(kb) else ""

        def _active_exts() -> set:
            exts = _rag_cfg.get("index_extensions", None)
            return set(exts) if exts else set(DEFAULT_EXTENSIONS)

        def _populate_files_list():
            files_list.clear()
            kb = _kb_path_now()
            if not kb:
                item = QListWidgetItem("  No knowledge base folder set.")
                item.setFlags(Qt.ItemFlag.NoItemFlags)
                files_list.addItem(item)
                return

            exts      = _active_exts()
            meta      = _load_file_meta()
            excluded  = load_exclusions(_excl_path)

            # Collect all files matching extension filter (ignoring exclusions — show them too)
            all_files: list[str] = []
            for root, _, names in os.walk(kb):
                for name in names:
                    ext = os.path.splitext(name)[1].lstrip(".").lower()
                    if ext and ext not in exts:
                        continue
                    all_files.append(os.path.join(root, name))
            all_files.sort()

            if not all_files:
                item = QListWidgetItem("  No files found for current extension filter.")
                item.setFlags(Qt.ItemFlag.NoItemFlags)
                files_list.addItem(item)
                return

            for abs_path in all_files:
                try:
                    rel = os.path.relpath(abs_path, kb)
                except ValueError:
                    rel = abs_path

                is_excluded = rel in excluded
                file_meta   = meta.get(abs_path, {})
                has_chunks  = bool(file_meta.get("chunk_ids"))

                if is_excluded:
                    status = _STATUS_EXCLUDED
                elif has_chunks:
                    status = _STATUS_INDEXED
                else:
                    status = _STATUS_PENDING

                item = QListWidgetItem()
                item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(Qt.CheckState.Unchecked if is_excluded else Qt.CheckState.Checked)
                item.setText(f"  {rel}    {status}")
                item.setData(Qt.ItemDataRole.UserRole, (abs_path, rel))

                if status == _STATUS_INDEXED:
                    item.setForeground(files_list.palette().text())
                elif status == _STATUS_PENDING:
                    item.setForeground(files_list.palette().mid())
                else:
                    item.setForeground(files_list.palette().placeholderText())

                files_list.addItem(item)

        _populate_files_list()

        def _on_file_item_changed(item: QListWidgetItem):
            data = item.data(Qt.ItemDataRole.UserRole)
            if data is None:
                return
            abs_path, rel = data
            checked = item.checkState() == Qt.CheckState.Checked

            files_list.blockSignals(True)
            try:
                excluded = load_exclusions(_excl_path)
                if not checked:
                    # Exclude: remove chunks from DB, remove from meta, save exclusion
                    excluded.add(rel)
                    save_exclusions(_excl_path, excluded)
                    meta = _load_file_meta()
                    chunk_ids = meta.get(abs_path, {}).get("chunk_ids", [])
                    _delete_chunks_from_db(chunk_ids)
                    if abs_path in meta:
                        del meta[abs_path]
                        _save_file_meta(meta)
                    item.setText(f"  {rel}    {_STATUS_EXCLUDED}")
                    item.setForeground(files_list.palette().placeholderText())
                else:
                    # Include: remove from exclusions
                    excluded.discard(rel)
                    save_exclusions(_excl_path, excluded)
                    if rag_auto_checkbox.isChecked():
                        item.setText(f"  {rel}    ⟳ indexing…")
                        item.setForeground(files_list.palette().mid())
                    else:
                        item.setText(f"  {rel}    {_STATUS_PENDING}")
                        item.setForeground(files_list.palette().mid())
            finally:
                files_list.blockSignals(False)

            if checked and rag_auto_checkbox.isChecked():
                _on_rag_reindex()

        files_list.itemChanged.connect(_on_file_item_changed)

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
                logger.warning("failed to persist rag setting to config", exc_info=True)

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
                logger.warning("failed to persist llama setting to config", exc_info=True)

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

        def _on_rag_rerank_changed(state):
            enabled = rag_rerank_checkbox.isChecked()
            _save_rag_key("rerank", enabled)
            rag_rerank_combo.setEnabled(enabled)

        def _on_rag_rerank_model_changed(idx):
            val = rag_rerank_combo.itemData(idx) or ""
            _save_rag_key("rerank_model", val)
            if val and not _is_cached(val, _rnk_cache_map):
                from PyQt6.QtWidgets import QMessageBox
                QMessageBox.information(
                    dlg, "Rerank model",
                    "This model is not downloaded yet.\n\n"
                    "It will be downloaded automatically on the first RAG query\n"
                    "with re-ranking enabled."
                )

        _spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        _spinner_idx = [0]

        def _on_rag_reindex():
            kb_path = rag_path_edit.text().strip()
            if not kb_path or not os.path.isdir(kb_path):
                from PyQt6.QtWidgets import QMessageBox
                QMessageBox.warning(dlg, "RAG", "Knowledge base folder not found.\nCheck the path in AI Settings > RAG.")
                return
            model_name = rag_model_combo.currentData()
            _exts_list = _rag_cfg.get("index_extensions", list(DEFAULT_EXTENSIONS))
            allowed_extensions = set(_exts_list) if _exts_list else None
            excluded_rel = load_exclusions(_excl_path)
            from core.rag.index_worker import IndexWorker
            worker = IndexWorker(kb_path, getattr(c, "base_path", ""), model_name, allowed_extensions, excluded_rel)
            c._rag_index_worker = worker
            rag_reindex_btn.setEnabled(False)
            rag_delete_btn.setEnabled(False)
            rag_status_label.setText("⟳ Starting indexing…")
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
                short_g = filename[:18] + "…" if len(filename) > 20 else filename
                c.flash_status(f"⟳ {current}/{total}  {short_g}")

            def _on_finished(result):
                spinner_timer.stop()
                rag_reindex_btn.setText("⟳ Refresh index")
                rag_reindex_btn.setEnabled(True)
                rag_delete_btn.setEnabled(True)
                if result == "OK":
                    rag_status_label.setText("✔ Indexing complete.")
                    _populate_files_list()
                    rag_status_label.setStyleSheet("color: green; font-size: 11px;")
                else:
                    rag_status_label.setText(f"✖ {result}")
                    rag_status_label.setStyleSheet("color: red; font-size: 11px;")
                c._rag_index_worker = None
                if result == "OK":
                    c.flash_status("✔ RAG indexing complete")
                else:
                    c.flash_status(f"✖ {result[:40]}")

            c.flash_status("⟳ Starting indexing…")
            QApplication.processEvents()

            worker.model_loading.connect(
                lambda downloading: c.flash_status(
                    "⟳ Downloading embedding model… (first use)" if downloading
                    else "⟳ Loading embedding model…"
                )
            )
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
                _populate_files_list()
            except Exception as e:
                QMessageBox.critical(dlg, "Error", f"Failed to delete database:\n{e}")

        def _on_settings_agent_role_changed(idx):
            val = settings_agent_role_combo.currentText()
            _save_llama_key("agent_role", val)
            c.apply_agent_files(val, settings_skills_combo.currentText(), settings_goal_combo.currentText())

        def _on_settings_skills_changed(idx):
            val = settings_skills_combo.currentText()
            _save_llama_key("skills_set", val)
            c.apply_agent_files(settings_agent_role_combo.currentText(), val, settings_goal_combo.currentText())

        def _on_settings_goal_changed(idx):
            val = settings_goal_combo.currentText()
            _save_llama_key("goal", val)
            c.apply_agent_files(settings_agent_role_combo.currentText(), settings_skills_combo.currentText(), val)

        rag_model_combo.currentIndexChanged.connect(_on_rag_model_changed)
        rag_radio_braindump.toggled.connect(_on_rag_braindump_toggled)
        rag_radio_custom.toggled.connect(_on_rag_custom_toggled)
        rag_browse_btn.clicked.connect(_on_rag_browse)
        rag_auto_checkbox.stateChanged.connect(_on_rag_auto_index_changed)
        rag_rerank_checkbox.stateChanged.connect(_on_rag_rerank_changed)
        rag_rerank_combo.currentIndexChanged.connect(_on_rag_rerank_model_changed)
        rag_reindex_btn.clicked.connect(_on_rag_reindex)
        rag_delete_btn.clicked.connect(_on_rag_delete_db)
        settings_agent_role_combo.currentIndexChanged.connect(_on_settings_agent_role_changed)
        settings_skills_combo.currentIndexChanged.connect(_on_settings_skills_changed)
        settings_goal_combo.currentIndexChanged.connect(_on_settings_goal_changed)

        # ── API Providers group ───────────────────────────────────────────────
        import threading
        import urllib.request
        import urllib.error
        import stat

        _PROVIDER_TYPES    = ["ollama", "openai", "anthropic", "groq", "gemini",
                              "openrouter", "huggingface", "mistral", "deepseek",
                              "xai", "cerebras", "together", "perplexity", "fireworks",
                              "llamacpp", "lmstudio", "jan", "koboldcpp"]
        _PROVIDER_BASE_URL = {
            "ollama":       "http://localhost:11434",
            "openai":       "https://api.openai.com/v1",
            "anthropic":    "https://api.anthropic.com/v1",
            "groq":         "https://api.groq.com/openai/v1",
            "gemini":       "https://generativelanguage.googleapis.com/v1beta/openai",
            "openrouter":   "https://openrouter.ai/api/v1",
            "huggingface":  "https://router.huggingface.co/featherless-ai/v1",
            "mistral":      "https://api.mistral.ai/v1",
            "deepseek":     "https://api.deepseek.com/v1",
            "xai":          "https://api.x.ai/v1",
            "cerebras":     "https://api.cerebras.ai/v1",
            "together":     "https://api.together.xyz/v1",
            "perplexity":   "https://api.perplexity.ai",
            "fireworks":    "https://api.fireworks.ai/inference/v1",
            "llamacpp":     "http://localhost:8080/v1",
            "lmstudio":     "http://localhost:1234/v1",
            "jan":          "http://localhost:1337/v1",
            "koboldcpp":    "http://localhost:5001/v1",
            "custom":       "",
        }
        _base_dir_prov  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _api_keys_path  = os.path.join(
            getattr(c, "base_path", _base_dir_prov), "appdata", "api_keys.json"
        )
        _api_profiles_path = getattr(c, "api_profiles_path",
            os.path.join(getattr(c, "base_path", _base_dir_prov), "appdata", "api_profiles.json")
        )

        # ── persistence helpers ───────────────────────────────────────────────
        _KR_SERVICE = "purrsh3ll"

        def _load_file_keys():
            try:
                if os.path.exists(_api_keys_path):
                    with open(_api_keys_path, "r", encoding="utf-8") as f:
                        return json.load(f)
            except Exception:
                logger.debug("failed to read API keys file, using empty", exc_info=True)
            return {}

        def _write_file_keys(keys):
            try:
                with open(_api_keys_path, "w", encoding="utf-8") as f:
                    json.dump(keys, f, indent=2, ensure_ascii=False)
                os.chmod(_api_keys_path, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                logger.warning("failed to persist API keys file (or set 0600 perms)", exc_info=True)

        def _get_api_key(profile_name):
            """Read key: keyring first, file fallback."""
            try:
                import keyring
                val = keyring.get_password(_KR_SERVICE, profile_name)
                if val:
                    return val
            except Exception:
                logger.debug("keyring get_password unavailable, falling back to file", exc_info=True)
            return _load_file_keys().get(profile_name, "")

        def _save_api_key(profile_name, key):
            if key:
                try:
                    import keyring
                    keyring.set_password(_KR_SERVICE, profile_name, key)
                    # migrate: remove from file if present
                    _fkeys = _load_file_keys()
                    if profile_name in _fkeys:
                        _fkeys.pop(profile_name)
                        _write_file_keys(_fkeys)
                    return
                except Exception:
                    logger.debug("keyring set_password unavailable, falling back to file", exc_info=True)
                # keyring unavailable — fallback to file
                _fkeys = _load_file_keys()
                _fkeys[profile_name] = key
                _write_file_keys(_fkeys)
            else:
                # delete from both
                try:
                    import keyring
                    keyring.delete_password(_KR_SERVICE, profile_name)
                except Exception:
                    logger.debug("keyring delete_password unavailable or key absent", exc_info=True)
                _fkeys = _load_file_keys()
                if profile_name in _fkeys:
                    _fkeys.pop(profile_name)
                    _write_file_keys(_fkeys)

        def _remove_api_key(profile_name):
            _save_api_key(profile_name, "")

        def _rename_api_key(old_name, new_name):
            key = _get_api_key(old_name)
            _remove_api_key(old_name)
            if key:
                _save_api_key(new_name, key)

        def _load_providers_config():
            try:
                if os.path.exists(_api_profiles_path):
                    with open(_api_profiles_path, "r", encoding="utf-8") as f:
                        return json.load(f)
            except Exception:
                logger.debug("failed to read API providers config, using empty", exc_info=True)
            return {}

        def _save_providers_to_config(profiles_list, active_name):
            try:
                os.makedirs(os.path.dirname(_api_profiles_path), exist_ok=True)
                data = {"active": active_name, "profiles": profiles_list}
                with open(_api_profiles_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            except Exception:
                logger.warning("failed to persist API providers config", exc_info=True)

        def _collect_profiles_from_table():
            profiles = []
            for r in range(providers_table.rowCount()):
                profiles.append(_table_row_to_dict(r))
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
            # sync chat panel model combobox
            chat_reload_fn = c.widgets.get("chat_combo_custom_reload")
            if chat_reload_fn is not None:
                chat_reload_fn()

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

            elif provider == "huggingface":
                # HF Hub API — models available via featherless-ai inference provider
                endpoint = (
                    "https://huggingface.co/api/models"
                    "?pipeline_tag=text-generation&inference_provider=featherless-ai&limit=300&sort=downloads&direction=-1"
                )
                headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
                if key:
                    headers["Authorization"] = f"Bearer {key}"
                req = urllib.request.Request(endpoint, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                # HF returns objects with "modelId" or "id" field
                return sorted(
                    m.get("modelId") or m.get("id")
                    for m in data
                    if m.get("modelId") or m.get("id")
                )

            else:
                # openai-compatible: openai / groq / gemini / openrouter / custom
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
        providers_table.setHorizontalHeaderLabels(["Name", "Provider", "Model", "Behavior"])
        providers_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        providers_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        providers_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        providers_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        providers_table.horizontalHeader().resizeSection(3, 80)
        providers_table.verticalHeader().setVisible(False)
        providers_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        providers_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        providers_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        providers_table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
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
            _b.setFocusPolicy(Qt.FocusPolicy.NoFocus)
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
                pdlg.setStyleSheet(c.messagebox_stylesheet + c.combo_stylesheet)
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
            try:
                f_provider.setStyleSheet(c.combo_stylesheet)
                _pv = QListView()
                _pv.setStyleSheet(c.combo_view_stylesheet)
                f_provider.setView(_pv)
            except Exception:
                pass
            f_url = QLineEdit(d.get("url", ""))

            # Model: editable combo + Fetch button
            f_model = QComboBox()
            f_model.setEditable(True)
            f_model.setMinimumWidth(160)
            if d.get("model"):
                f_model.addItem(d["model"])
                f_model.setCurrentText(d["model"])
            f_model.lineEdit().setPlaceholderText("e.g. llama3.2 / gpt-4o")
            try:
                f_model.setStyleSheet(c.combo_stylesheet)
                f_model.view().setStyleSheet(c.combo_view_stylesheet)
            except Exception:
                pass

            fetch_status = QLabel("")
            fetch_status.setStyleSheet("font-size: 11px; color: gray;")
            btn_fetch = QPushButton("Fetch models")
            btn_fetch.setFixedWidth(100)
            btn_fetch.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            model_row = QHBoxLayout()
            model_row.addWidget(f_model, 1)
            model_row.addWidget(btn_fetch)

            f_key = QLineEdit(d.get("key", ""))
            f_key.setPlaceholderText("API key")
            f_key.setEchoMode(QLineEdit.EchoMode.Password)
            _autofilled_key = [d.get("key", "")]  # tracks last autofilled value

            def _update_url_placeholder(idx=None):
                f_url.setPlaceholderText(
                    _PROVIDER_BASE_URL.get(f_provider.currentText(), "") or "Base URL"
                )

            def _autofill_key(idx=None):
                # Only autofill in Add mode (no defaults) or when field is empty/autofilled
                current = f_key.text()
                if current and current != _autofilled_key[0]:
                    return  # user typed something manually — don't overwrite
                provider = f_provider.currentText()
                # Find first existing profile with this provider that has a key
                for r in range(providers_table.rowCount()):
                    cell = providers_table.item(r, 1)
                    if cell and cell.text() == provider:
                        name = providers_table.item(r, 0)
                        if name:
                            key = _get_api_key(name.text())
                            if key:
                                f_key.setText(key)
                                _autofilled_key[0] = key
                                return
                # No match found — clear only if was autofilled
                if current == _autofilled_key[0]:
                    f_key.clear()
                    _autofilled_key[0] = ""

            f_provider.currentIndexChanged.connect(_update_url_placeholder)
            f_provider.currentIndexChanged.connect(_autofill_key)
            _update_url_placeholder()
            # Autofill on open only in Add mode (no pre-existing key)
            if not d.get("key"):
                _autofill_key()

            def _do_fetch():
                provider = f_provider.currentText()
                url      = f_url.text().strip()
                key      = f_key.text().strip()
                try:
                    models = _fetch_provider_models(provider, url, key)
                    return models, None
                except Exception as e:
                    return [], str(e)

            def _open_model_picker(models):
                picker = QDialog(pdlg)
                picker.setWindowTitle("Select model")
                picker.setModal(True)
                picker.resize(560, 420)
                try:
                    picker.setStyleSheet(c.messagebox_stylesheet)
                except Exception:
                    pass

                layout = QVBoxLayout(picker)
                layout.setContentsMargins(12, 12, 12, 12)
                layout.setSpacing(8)

                search = QLineEdit(picker)
                search.setPlaceholderText("Filter models…")
                search.setClearButtonEnabled(True)
                layout.addWidget(search)

                lw = QListWidget(picker)
                lw.setAlternatingRowColors(True)
                try:
                    lw.setStyleSheet(
                        "QListWidget { font-size: 12px; }"
                        "QListWidget::item { padding: 4px 8px; }"
                        "QListWidget::item:selected { color: palette(highlighted-text);"
                        " background: palette(highlight); }"
                    )
                except Exception:
                    pass
                for name in models:
                    lw.addItem(QListWidgetItem(name))
                # Pre-select current model if present
                current = f_model.currentText().strip()
                if current:
                    hits = lw.findItems(current, Qt.MatchFlag.MatchExactly)
                    if hits:
                        lw.setCurrentItem(hits[0])
                        lw.scrollToItem(hits[0])
                layout.addWidget(lw)

                btn_row = QHBoxLayout()
                btn_row.addStretch(1)
                btn_select = QPushButton("Select")
                btn_select.setFixedWidth(80)
                btn_cancel2 = QPushButton("Cancel")
                btn_cancel2.setFixedWidth(80)
                btn_row.addWidget(btn_select)
                btn_row.addWidget(btn_cancel2)
                layout.addLayout(btn_row)

                def _apply_filter(text):
                    txt = text.strip().lower()
                    for i in range(lw.count()):
                        item = lw.item(i)
                        item.setHidden(bool(txt) and txt not in item.text().lower())

                def _do_select():
                    sel = lw.currentItem()
                    if sel and not sel.isHidden():
                        f_model.blockSignals(True)
                        # Keep current items, just update the editable text
                        if f_model.findText(sel.text()) < 0:
                            f_model.insertItem(0, sel.text())
                        f_model.setCurrentText(sel.text())
                        f_model.blockSignals(False)
                        picker.accept()

                search.textChanged.connect(_apply_filter)
                lw.itemDoubleClicked.connect(lambda _: _do_select())
                btn_select.clicked.connect(_do_select)
                btn_cancel2.clicked.connect(picker.reject)

                # Select first visible item if nothing selected
                if not lw.currentItem():
                    for i in range(lw.count()):
                        if not lw.item(i).isHidden():
                            lw.setCurrentRow(i)
                            break

                picker.exec()

            def _on_fetch():
                btn_fetch.setEnabled(False)
                fetch_status.setText("Fetching…")
                fetch_status.setStyleSheet("font-size: 11px; color: gray;")
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
                        fetch_status.setText(f"{len(models)} models found")
                        fetch_status.setStyleSheet("font-size: 11px; color: green;")
                        _open_model_picker(models)

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
            btn_ok.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            btn_cancel.setFocusPolicy(Qt.FocusPolicy.NoFocus)
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
                "btn_ok":   btn_ok,
            }

        # ── table helpers ─────────────────────────────────────────────────────
        def _table_row_to_dict(row):
            name_item = providers_table.item(row, 0)
            meta = (name_item.data(Qt.ItemDataRole.UserRole) or {}) if name_item else {}
            if not isinstance(meta, dict):
                meta = {"url": meta}
            return {
                "name":               name_item.text() if name_item else "",
                "provider":           providers_table.item(row, 1).text() if providers_table.item(row, 1) else "",
                "model":              providers_table.item(row, 2).text() if providers_table.item(row, 2) else "",
                "url":                meta.get("url", ""),
                "disable_thinking":   meta.get("disable_thinking", False),
                "hide_thinking":      meta.get("hide_thinking", False),
                "fast_answers":       meta.get("fast_answers", False),
                "custom_params":      meta.get("custom_params", ""),
                "custom_system":      meta.get("custom_system", ""),
                "temperature":        meta.get("temperature", ""),
                "context_tokens":     meta.get("context_tokens", 0),
                "tools_user_override": meta.get("tools_user_override"),
                "vision_user_override": meta.get("vision_user_override"),
                "audio_user_override":  meta.get("audio_user_override"),
            }

        def _set_row_meta(row, profile):
            name_item = providers_table.item(row, 0)
            if name_item:
                name_item.setData(Qt.ItemDataRole.UserRole, {
                    "url":               profile.get("url", ""),
                    "disable_thinking":  bool(profile.get("disable_thinking", False)),
                    "hide_thinking":     bool(profile.get("hide_thinking", False)),
                    "fast_answers":      bool(profile.get("fast_answers", False)),
                    "custom_params":     profile.get("custom_params", ""),
                    "custom_system":     profile.get("custom_system", ""),
                    "temperature":       profile.get("temperature", ""),
                    "context_tokens":    int(profile.get("context_tokens", 0)),
                    "tools_user_override": profile.get("tools_user_override"),
                    "vision_user_override": profile.get("vision_user_override"),
                    "audio_user_override":  profile.get("audio_user_override"),
                })

        def _insert_table_row(row_idx, profile):
            providers_table.insertRow(row_idx)
            for col, key in enumerate(["name", "provider", "model"]):
                item = QTableWidgetItem(profile.get(key, ""))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                providers_table.setItem(row_idx, col, item)
            _set_row_meta(row_idx, profile)
            # Gear button in Behavior column — centered wrapper
            gear_btn = QPushButton("⚙")
            gear_btn.setFixedSize(24, 20)
            gear_btn.setToolTip("Behavior settings")
            def _on_gear(checked=False, b=gear_btn):
                for _r in range(providers_table.rowCount()):
                    if providers_table.cellWidget(_r, 3).findChild(QPushButton) is b:
                        _on_behavior(_r)
                        return
            gear_btn.clicked.connect(_on_gear)
            _cell_w = QWidget()
            _cell_layout = QHBoxLayout(_cell_w)
            _cell_layout.setContentsMargins(0, 0, 0, 0)
            _cell_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            _cell_layout.addWidget(gear_btn)
            providers_table.setCellWidget(row_idx, 3, _cell_w)

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

        def _lookup_ctx_window(profile):
            """Return context window (int) for the given profile, or None if unknown."""
            try:
                _reg_path = os.path.join(
                    getattr(c, "base_path", _base_dir_prov), "appdata", "model_ctx_registry.json"
                )
                with open(_reg_path, encoding="utf-8") as _f:
                    _reg = json.load(_f)
            except Exception:
                return None
            provider = profile.get("provider", "").lower()
            model    = profile.get("model", "")
            # Normalize model name:
            # 1. Strip "models/" prefix (Gemini API format: "models/gemini-2.5-flash")
            if model.lower().startswith("models/"):
                model = model[7:]
            # 2. Strip OpenRouter variant suffixes (":free", ":extended", ":nitro", etc.)
            if ":" in model:
                model = model.split(":")[0]
            model_lc = model.lower()
            section  = _reg.get(provider, {})
            if not section:
                return None
            models = section.get("models", {})
            # exact match (case-insensitive)
            for key, val in models.items():
                if model_lc == key.lower():
                    return val
            # exact match preserving original case (for HuggingFace Qwen/Qwen3-4B style)
            for key, val in models.items():
                if model == key:
                    return val
            # prefix match (case-insensitive)
            for key, val in models.items():
                if model_lc.startswith(key.lower()):
                    return val
            return section.get("default")

        def _lookup_tools_support(profile):
            """Return (effective_default: bool|None, tools_user_override: bool|None).
            effective_default: True/False = detected, None = unknown/model-dependent.
            """
            try:
                _reg_path = os.path.join(
                    getattr(c, "base_path", _base_dir_prov), "appdata", "model_ctx_registry.json"
                )
                with open(_reg_path, encoding="utf-8") as _f:
                    _reg = json.load(_f)
            except Exception:
                return None, None
            provider = profile.get("provider", "").lower()
            model    = profile.get("model", "")
            if model.lower().startswith("models/"):
                model = model[7:]
            if ":" in model:
                model = model.split(":")[0]
            section = _reg.get(provider, {})
            if not section:
                return None, None
            tools_default = section.get("tools_default")       # True, False, or None
            no_tools      = section.get("no_tools", [])
            yes_tools     = section.get("tools", [])            # positive opt-in (e.g. Ollama)
            ml            = model.lower()
            in_no_tools   = model in no_tools or ml in [m.lower() for m in no_tools]
            in_yes_tools  = model in yes_tools or ml in [m.lower() for m in yes_tools]
            if in_no_tools:
                eff = False
            elif in_yes_tools:
                eff = True
            elif tools_default is None:
                eff = None
            else:
                eff = tools_default
            user_ov = section.get("tools_user_override")       # read provider-level stored override
            # Profile-level override takes priority over provider-level registry value
            profile_ov = profile.get("tools_user_override")    # True, False, or None/missing
            final_ov = profile_ov if profile_ov is not None else user_ov
            return eff, final_ov

        def _lookup_multimodal(profile):
            """Return (vision_default: bool, audio_default: bool) — whether the
            profile's model appears on the registry vision/audio (multimodal
            input) capability lists."""
            try:
                _reg_path = os.path.join(
                    getattr(c, "base_path", _base_dir_prov), "appdata", "model_ctx_registry.json"
                )
                with open(_reg_path, encoding="utf-8") as _f:
                    _reg = json.load(_f)
            except Exception:
                return False, False
            provider = profile.get("provider", "").lower()
            model    = profile.get("model", "")
            if model.lower().startswith("models/"):
                model = model[7:]
            if ":" in model:
                model = model.split(":")[0]
            section = _reg.get(provider, {})
            if not section:
                return False, False
            ml = model.lower()
            vision_list = section.get("vision", []) or []
            audio_list  = section.get("audio", []) or []
            vision_def = model in vision_list or ml in [m.lower() for m in vision_list]
            audio_def  = model in audio_list  or ml in [m.lower() for m in audio_list]
            return vision_def, audio_def

        def _on_behavior(row):
            profile = _table_row_to_dict(row)
            bdlg = QDialog(dlg)
            bdlg.setWindowTitle(f"Behavior — {profile['name']}")
            bdlg.setModal(True)
            bdlg.resize(440, 150)
            bdlg.setSizeGripEnabled(True)
            try:
                bdlg.setStyleSheet(c.messagebox_stylesheet)
            except Exception:
                pass
            bform = QVBoxLayout(bdlg)
            bform.setContentsMargins(16, 16, 16, 12)
            bform.setSpacing(8)

            from math import log, exp
            # Provider-aware unknown-model default (cloud 200k / local runtimes
            # 32k / ollama 4k), kept in sync with the tooltip and live CTX bar.
            try:
                _CTX_SAFE_DEFAULT = c._fallback_ctx_window(profile.get("provider", ""))
            except Exception:
                _CTX_SAFE_DEFAULT = 32_768
            _CTX_MIN, _CTX_MAX = 512, 2_000_000
            _SLIDER_STEPS = 1000
            _LOG_MIN = log(_CTX_MIN)
            _LOG_MAX = log(_CTX_MAX)

            def _val_to_pos(v):
                return int(_SLIDER_STEPS * (log(max(v, _CTX_MIN)) - _LOG_MIN) / (_LOG_MAX - _LOG_MIN))

            def _pos_to_val(p):
                return int(exp(_LOG_MIN + (p / _SLIDER_STEPS) * (_LOG_MAX - _LOG_MIN)))

            ctx_registry_val = _lookup_ctx_window(profile)
            ctx_default = ctx_registry_val if ctx_registry_val else _CTX_SAFE_DEFAULT
            saved_ctx = int(profile.get("context_tokens") or 0)
            ctx_initial = saved_ctx if saved_ctx >= _CTX_MIN else ctx_default

            class _CtxSpinBox(QSpinBox):
                def textFromValue(self, v):
                    return f"{v:,}".replace(",", " ")
                def valueFromText(self, t):
                    try:
                        return int(t.replace(" ", "").replace(",", ""))
                    except ValueError:
                        return self.minimum()
                def validate(self, inp, pos):
                    from PyQt6.QtGui import QValidator
                    clean = inp.replace(" ", "").replace(",", "")
                    if not clean:
                        return QValidator.State.Intermediate, inp, pos
                    if clean.isdigit():
                        v = int(clean)
                        if self.minimum() <= v <= self.maximum():
                            return QValidator.State.Acceptable, inp, pos
                        return QValidator.State.Intermediate, inp, pos
                    return QValidator.State.Invalid, inp, pos
                def stepBy(self, steps):
                    v = self.value()
                    if v < 4_096:
                        delta = 512
                    elif v < 16_384:
                        delta = 1_024
                    elif v < 65_536:
                        delta = 4_096
                    elif v < 262_144:
                        delta = 8_192
                    else:
                        delta = 16_384
                    self.setValue(max(self.minimum(), min(self.maximum(), v + steps * delta)))

            if ctx_registry_val:
                ctx_info_text = f"Context window: {ctx_registry_val:,}".replace(",", " ") + " tokens"
            else:
                safe_str = f"{_CTX_SAFE_DEFAULT:,}".replace(",", " ")
                ctx_info_text = f"Context window: unknown model — safe default: {safe_str} tokens"
            ctx_info_lbl = QLabel(ctx_info_text)
            ctx_info_lbl.setStyleSheet("font-size: 11px;")
            bform.addWidget(ctx_info_lbl)

            cb_ctx_override = QCheckBox("Override context window for prompt compensation")
            cb_ctx_override.setChecked(saved_ctx >= _CTX_MIN)
            bform.addWidget(cb_ctx_override)

            ctx_override_widget = QWidget()
            ctx_override_layout = QVBoxLayout(ctx_override_widget)
            ctx_override_layout.setContentsMargins(0, 0, 0, 0)
            ctx_override_layout.setSpacing(4)

            sb_ctx = _CtxSpinBox()
            sb_ctx.setRange(_CTX_MIN, _CTX_MAX)
            sb_ctx.setValue(ctx_initial)
            sb_ctx.setFixedWidth(100)

            ctx_reset_btn = QPushButton("Default")
            ctx_reset_btn.setFixedWidth(62)
            default_str = f"{ctx_default:,}".replace(",", " ")
            ctx_reset_btn.setToolTip(f"Reset to registry default: {default_str} tokens")
            ctx_reset_btn.clicked.connect(lambda: sb_ctx.setValue(ctx_default))

            ctx_row = QHBoxLayout()
            ctx_row.addWidget(sb_ctx)
            ctx_row.addWidget(QLabel("tokens"))
            ctx_row.addStretch(1)
            ctx_row.addWidget(ctx_reset_btn)

            ctx_slider = QSlider(Qt.Orientation.Horizontal)
            ctx_slider.setRange(0, _SLIDER_STEPS)
            ctx_slider.setValue(_val_to_pos(ctx_initial))

            _ctx_updating = [False]

            def _on_slider(pos):
                if _ctx_updating[0]:
                    return
                _ctx_updating[0] = True
                sb_ctx.setValue(_pos_to_val(pos))
                _ctx_updating[0] = False

            def _on_spinbox(val):
                if _ctx_updating[0]:
                    return
                _ctx_updating[0] = True
                ctx_slider.setValue(_val_to_pos(val))
                _ctx_updating[0] = False

            ctx_slider.valueChanged.connect(_on_slider)
            sb_ctx.valueChanged.connect(_on_spinbox)

            ctx_override_layout.addLayout(ctx_row)
            ctx_override_layout.addWidget(ctx_slider)

            ctx_override_widget.setVisible(saved_ctx >= _CTX_MIN)

            def _on_ctx_override_toggled(checked):
                ctx_override_widget.setVisible(checked)
                w = bdlg.width()
                bdlg.adjustSize()
                bdlg.resize(w, bdlg.height())

            cb_ctx_override.toggled.connect(_on_ctx_override_toggled)
            bform.addWidget(ctx_override_widget)

            # --- Function calling checkbox ---
            _tools_eff_default, _tools_saved_override = _lookup_tools_support(profile)
            if _tools_eff_default is True:
                _tools_default_label = "default: yes"
            else:
                _tools_default_label = "default: no"
            _tools_checked = _tools_saved_override if _tools_saved_override is not None else (_tools_eff_default or False)
            _tools_override_val = [_tools_saved_override]

            _fc_row = QHBoxLayout()
            cb_tools = QCheckBox(f"Function calling  ({_tools_default_label})")
            cb_tools.setChecked(bool(_tools_checked))
            tools_default_btn = QPushButton("Default")
            tools_default_btn.setFixedWidth(62)
            tools_default_btn.setToolTip("Reset to auto-detected default")

            def _on_tools_default():
                _tools_override_val[0] = None
                cb_tools.setChecked(bool(_tools_eff_default) if _tools_eff_default is not None else False)

            def _on_tools_toggled(checked):
                _tools_override_val[0] = checked

            tools_default_btn.clicked.connect(_on_tools_default)
            cb_tools.toggled.connect(_on_tools_toggled)
            _fc_row.addWidget(cb_tools)
            _fc_row.addStretch(1)
            _fc_row.addWidget(tools_default_btn)
            bform.addLayout(_fc_row)
            # --- end Function calling ---

            # --- Vision / Audio (multimodal input) checkboxes ---
            _vision_eff_default, _audio_eff_default = _lookup_multimodal(profile)
            _vision_saved_override = profile.get("vision_user_override")
            _audio_saved_override  = profile.get("audio_user_override")
            _vision_override_val = [_vision_saved_override]
            _audio_override_val  = [_audio_saved_override]

            _vis_row = QHBoxLayout()
            cb_vision = QCheckBox(
                f"Vision  (default: {'yes' if _vision_eff_default else 'no'})"
            )
            cb_vision.setChecked(bool(
                _vision_saved_override if _vision_saved_override is not None else _vision_eff_default
            ))
            vision_default_btn = QPushButton("Default")
            vision_default_btn.setFixedWidth(62)
            vision_default_btn.setToolTip("Reset to auto-detected default")

            def _on_vision_default():
                _vision_override_val[0] = None
                cb_vision.setChecked(bool(_vision_eff_default))

            def _on_vision_toggled(checked):
                _vision_override_val[0] = checked

            vision_default_btn.clicked.connect(_on_vision_default)
            cb_vision.toggled.connect(_on_vision_toggled)
            _vis_row.addWidget(cb_vision)
            _vis_row.addStretch(1)
            _vis_row.addWidget(vision_default_btn)
            bform.addLayout(_vis_row)

            _aud_row = QHBoxLayout()
            cb_audio = QCheckBox(
                f"Audio  (default: {'yes' if _audio_eff_default else 'no'})"
            )
            cb_audio.setChecked(bool(
                _audio_saved_override if _audio_saved_override is not None else _audio_eff_default
            ))
            audio_default_btn = QPushButton("Default")
            audio_default_btn.setFixedWidth(62)
            audio_default_btn.setToolTip("Reset to auto-detected default")

            def _on_audio_default():
                _audio_override_val[0] = None
                cb_audio.setChecked(bool(_audio_eff_default))

            def _on_audio_toggled(checked):
                _audio_override_val[0] = checked

            audio_default_btn.clicked.connect(_on_audio_default)
            cb_audio.toggled.connect(_on_audio_toggled)
            _aud_row.addWidget(cb_audio)
            _aud_row.addStretch(1)
            _aud_row.addWidget(audio_default_btn)
            bform.addLayout(_aud_row)
            # --- end Vision / Audio ---

            saved_custom = profile.get("custom_params", "")
            is_custom    = bool(saved_custom)
            is_ollama    = profile.get("provider", "") == "ollama"

            # Temperature — applies to every provider (Ollama native, OpenAI-compat,
            # Anthropic) in the ps* tools and, via a baked Modelfile, in ai_chat.
            _TEMP_DEFAULT = 0.8
            _raw_temp = profile.get("temperature", "")
            try:
                saved_temp = float(_raw_temp) if _raw_temp not in (None, "") else None
            except (TypeError, ValueError):
                saved_temp = None
            is_temp      = saved_temp is not None and not is_custom
            temp_initial = saved_temp if saved_temp is not None else _TEMP_DEFAULT

            cb_think      = QCheckBox("Disable thinking")
            cb_hide_think = QCheckBox("Hide thinking output")
            cb_fast       = QCheckBox("Fast answers  (short responses)")
            cb_temp       = QCheckBox("Temperature  (sampling randomness)")
            cb_custom     = QCheckBox("Custom parameters")
            cb_think.setChecked(bool(profile.get("disable_thinking", False)) and not is_custom)
            cb_hide_think.setChecked(bool(profile.get("hide_thinking", False)))
            cb_fast.setChecked(bool(profile.get("fast_answers",     False)) and not is_custom)
            cb_temp.setChecked(is_temp)
            cb_custom.setChecked(is_custom)
            # "Disable thinking" is Ollama-only; hide it for all other providers
            cb_think.setVisible(is_ollama)

            temp_widget = QWidget()
            temp_row = QHBoxLayout(temp_widget)
            temp_row.setContentsMargins(0, 0, 0, 0)
            sb_temp = QDoubleSpinBox()
            sb_temp.setRange(0.0, 2.0)
            sb_temp.setSingleStep(0.1)
            sb_temp.setDecimals(2)
            sb_temp.setValue(temp_initial)
            sb_temp.setFixedWidth(80)
            temp_reset_btn = QPushButton("Default")
            temp_reset_btn.setFixedWidth(62)
            temp_reset_btn.setToolTip(f"Reset to {_TEMP_DEFAULT}")
            temp_reset_btn.clicked.connect(lambda: sb_temp.setValue(_TEMP_DEFAULT))
            temp_row.addWidget(sb_temp)
            temp_row.addWidget(QLabel("0 = deterministic · higher = more random"))
            temp_row.addStretch(1)
            temp_row.addWidget(temp_reset_btn)
            temp_widget.setVisible(is_temp)

            # System prompt — plain-text model role/behaviour, saved to
            # custom_system and prepended as a system message (psask/pschat/ai_chat).
            # Mutually exclusive with Custom parameters, whose JSON can carry its
            # own "system" key.
            saved_system = profile.get("custom_system", "")
            is_system    = bool(saved_system) and not is_custom
            cb_system    = QCheckBox("System prompt  (model role / behavior)")
            cb_system.setChecked(is_system)

            _SYS_PLACEHOLDER = (
                "You are a senior penetration tester assisting on an authorized "
                "engagement. Be concise, precise, and practical."
            )
            system_edit = QTextEdit()
            system_edit.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
            system_edit.setMinimumHeight(72)
            system_edit.setVisible(is_system)

            def _set_sys_placeholder():
                system_edit.setPlainText(_SYS_PLACEHOLDER)
                system_edit.setStyleSheet("color: gray;")

            def _clear_sys_placeholder():
                if system_edit.toPlainText() == _SYS_PLACEHOLDER:
                    system_edit.clear()
                    system_edit.setStyleSheet("")

            def _restore_sys_placeholder_if_empty():
                if not system_edit.toPlainText().strip():
                    _set_sys_placeholder()

            if saved_system:
                system_edit.setPlainText(saved_system)
            else:
                _set_sys_placeholder()

            def _sys_focus_in(e):
                _clear_sys_placeholder()
                QTextEdit.focusInEvent(system_edit, e)

            def _sys_focus_out(e):
                _restore_sys_placeholder_if_empty()
                QTextEdit.focusOutEvent(system_edit, e)

            system_edit.focusInEvent  = _sys_focus_in
            system_edit.focusOutEvent = _sys_focus_out

            _PLACEHOLDER = (
                '{"temperature": 0.7,\n'
                '"thinking": {"type": "disabled"},\n'
                '"system": "You are Skynet, an AI assistant'
                ' helping me with tasks. Be concise and precise."}'
            )
            custom_edit = QTextEdit()
            custom_edit.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
            custom_edit.setMinimumHeight(72)
            custom_edit.setVisible(is_custom)

            def _set_placeholder():
                custom_edit.setPlainText(_PLACEHOLDER)
                custom_edit.setStyleSheet("color: gray;")

            def _clear_placeholder():
                if custom_edit.toPlainText() == _PLACEHOLDER:
                    custom_edit.clear()
                    custom_edit.setStyleSheet("")

            def _restore_placeholder_if_empty():
                if not custom_edit.toPlainText().strip():
                    _set_placeholder()

            if saved_custom:
                custom_edit.setPlainText(saved_custom)
            else:
                _set_placeholder()

            def _focus_in(e):
                _clear_placeholder()
                QTextEdit.focusInEvent(custom_edit, e)

            def _focus_out(e):
                _restore_placeholder_if_empty()
                QTextEdit.focusOutEvent(custom_edit, e)

            custom_edit.focusInEvent  = _focus_in
            custom_edit.focusOutEvent = _focus_out

            def _on_temp_toggled():
                _is = cb_temp.isChecked()
                if _is and cb_custom.isChecked():
                    cb_custom.setChecked(False)
                temp_widget.setVisible(_is)
                w = bdlg.width()
                bdlg.adjustSize()
                bdlg.resize(w, bdlg.height())

            def _on_system_toggled():
                _is = cb_system.isChecked()
                if _is and cb_custom.isChecked():
                    cb_custom.setChecked(False)
                system_edit.setVisible(_is)
                w = bdlg.width()
                bdlg.adjustSize()
                bdlg.resize(w, bdlg.height())

            def _on_custom_toggled():
                _is = cb_custom.isChecked()
                if _is:
                    cb_think.setChecked(False)
                    cb_hide_think.setChecked(False)
                    cb_fast.setChecked(False)
                    cb_temp.setChecked(False)
                    cb_system.setChecked(False)
                custom_edit.setVisible(_is)
                bdlg.adjustSize()

            def _on_other_checkbox_checked(state):
                if state and cb_custom.isChecked():
                    cb_custom.setChecked(False)

            cb_think.stateChanged.connect(_on_other_checkbox_checked)
            cb_hide_think.stateChanged.connect(_on_other_checkbox_checked)
            cb_fast.stateChanged.connect(_on_other_checkbox_checked)
            cb_temp.stateChanged.connect(_on_temp_toggled)
            cb_system.stateChanged.connect(_on_system_toggled)
            cb_custom.stateChanged.connect(_on_custom_toggled)

            bform.addWidget(cb_think)
            bform.addWidget(cb_hide_think)
            bform.addWidget(cb_fast)
            bform.addWidget(cb_temp)
            bform.addWidget(temp_widget)
            bform.addWidget(cb_system)
            bform.addWidget(system_edit, stretch=1)
            bform.addWidget(cb_custom)
            bform.addWidget(custom_edit, stretch=1)

            bbtn_row = QHBoxLayout()
            bbtn_ok     = QPushButton("OK")
            bbtn_cancel = QPushButton("Cancel")
            bbtn_ok.setFixedWidth(70)
            bbtn_cancel.setFixedWidth(70)
            bbtn_row.addStretch(1)
            bbtn_row.addWidget(bbtn_ok)
            bbtn_row.addWidget(bbtn_cancel)
            bform.addLayout(bbtn_row)
            bbtn_ok.clicked.connect(bdlg.accept)
            bbtn_cancel.clicked.connect(bdlg.reject)
            if bdlg.exec() != QDialog.DialogCode.Accepted:
                return
            profile["context_tokens"]      = sb_ctx.value() if cb_ctx_override.isChecked() else 0
            profile["tools_user_override"] = _tools_override_val[0]
            profile["vision_user_override"] = _vision_override_val[0]
            profile["audio_user_override"]  = _audio_override_val[0]
            profile["disable_thinking"] = cb_think.isChecked()
            profile["hide_thinking"]    = cb_hide_think.isChecked()
            profile["fast_answers"]     = cb_fast.isChecked()
            profile["temperature"]      = round(sb_temp.value(), 2) if cb_temp.isChecked() else ""
            _raw = custom_edit.toPlainText().strip()
            profile["custom_params"]    = (_raw if _raw != _PLACEHOLDER.strip() else "") if cb_custom.isChecked() else ""
            _raw_sys = system_edit.toPlainText().strip()
            profile["custom_system"]    = (_raw_sys if _raw_sys != _SYS_PLACEHOLDER else "") if cb_system.isChecked() else ""
            _set_row_meta(row, profile)
            _persist()

        def _on_add_provider():
            pdlg, fields = _build_profile_dialog("Add Provider Profile")

            def _warn(title, text):
                from PyQt6.QtWidgets import QMessageBox
                mb = QMessageBox(pdlg)
                mb.setWindowTitle(title)
                mb.setText(text)
                mb.setIcon(QMessageBox.Icon.Warning)
                try:
                    mb.setStyleSheet(c.messagebox_stylesheet)
                except Exception:
                    pass
                mb.exec()

            def _validate_and_accept():
                name = fields["name"].text().strip()
                if not name:
                    _warn("Name required", "Profile name cannot be empty.\nPlease enter a name and try again.")
                    return
                existing = [
                    providers_table.item(r, 0).text()
                    for r in range(providers_table.rowCount())
                    if providers_table.item(r, 0)
                ]
                if name in existing:
                    _warn("Duplicate name", f"A profile named \"{name}\" already exists.\nPlease choose a different name.")
                    return
                pdlg.accept()

            fields["btn_ok"].clicked.disconnect()
            fields["btn_ok"].clicked.connect(_validate_and_accept)

            if pdlg.exec() != QDialog.DialogCode.Accepted:
                return
            profile = _profile_from_fields(fields)
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
            current["key"] = _get_api_key(old_name)
            pdlg, fields = _build_profile_dialog("Edit Provider Profile", defaults=current)
            if pdlg.exec() != QDialog.DialogCode.Accepted:
                return
            profile = _profile_from_fields(fields)
            if not profile["name"]:
                return
            for col, k in enumerate(["name", "provider", "model"]):
                item = QTableWidgetItem(profile[k])
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                providers_table.setItem(row, col, item)
            # Preserve existing behavior settings, update url
            existing = _table_row_to_dict(row)
            profile["disable_thinking"] = existing.get("disable_thinking", False)
            profile["hide_thinking"]    = existing.get("hide_thinking", False)
            profile["fast_answers"]     = existing.get("fast_answers", False)
            profile["custom_params"]    = existing.get("custom_params", "")
            profile["custom_system"]    = existing.get("custom_system", "")
            profile["temperature"]      = existing.get("temperature", "")
            profile["context_tokens"]   = existing.get("context_tokens", 0)
            _set_row_meta(row, profile)
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
            from PyQt6.QtWidgets import QMessageBox
            reply = QMessageBox.question(
                dlg, "Remove profile",
                f"Remove profile \"{name}\"?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
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
        # ── Tab: Settings (AI/LLM) ────────────────────────────────────────────
        settings_scroll_content = QWidget()
        settings_scroll_content.setObjectName("ai_settings_scroll_content")
        settings_scroll_content.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        settings_scroll_layout = QVBoxLayout(settings_scroll_content)
        settings_scroll_layout.setContentsMargins(4, 4, 4, 4)
        settings_scroll_layout.setSpacing(8)
        settings_scroll_layout.addWidget(grp_llm)
        settings_scroll_layout.addWidget(grp_pstools)
        settings_scroll_layout.addStretch(1)

        settings_scroll = QScrollArea()
        settings_scroll.setObjectName("ai_settings_scroll")
        settings_scroll.setWidgetResizable(True)
        settings_scroll.setWidget(settings_scroll_content)
        settings_scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        # ── Tab: RAG ──────────────────────────────────────────────────────────
        rag_scroll_content = QWidget()
        rag_scroll_content.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        rag_scroll_layout = QVBoxLayout(rag_scroll_content)
        rag_scroll_layout.setContentsMargins(4, 4, 4, 4)
        rag_scroll_layout.setSpacing(8)
        rag_scroll_layout.addWidget(grp_rag)
        rag_scroll_layout.addStretch(1)

        rag_scroll = QScrollArea()
        rag_scroll.setWidgetResizable(True)
        rag_scroll.setWidget(rag_scroll_content)
        rag_scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        # ── Tab: Profiles (API Providers table) ───────────────────────────────
        profiles_tab = QWidget()
        profiles_tab_layout = QVBoxLayout(profiles_tab)
        profiles_tab_layout.setContentsMargins(8, 8, 8, 8)
        profiles_tab_layout.setSpacing(6)
        profiles_tab_layout.addWidget(grp_providers)

        # ── QTabWidget ────────────────────────────────────────────────────────
        tabs = QTabWidget(dlg)
        tabs.addTab(settings_scroll, "  Settings  ")
        tabs.addTab(rag_scroll, "  RAG  ")
        tabs.addTab(profiles_tab, "  Profiles  ")

        _bg  = c.actual_theme.get("background", {})
        _fg  = c.actual_theme.get("foreground", {})
        _bd  = c.actual_theme.get("border", {})
        tabs.setStyleSheet(f"""
            QTabBar::tab {{
                min-width: 90px;
                padding-top: 7px;
                padding-bottom: 7px;
                padding-left: 0px;
                padding-right: 0px;
                margin-left: 4px;
                margin-right: 4px;
                background: {_bg.get("tab_bar", "#3B3E40")};
                color: {_fg.get("tab_bar", "#ffffff")};
                border: 1px solid {_bd.get("default", "#555")};
                border-bottom: none;
                border-radius: 4px 4px 0 0;
            }}
            QTabBar::tab:first {{
                margin-left: 0px;
            }}
            QTabBar::tab:selected {{
                background: {_bg.get("tab_bar_selected", "#1E1F22")};
                color: {_fg.get("tab_bar_selected", "#ffffff")};
            }}
            QTabBar::tab:hover:!selected {{
                background: {_bg.get("buttons_hover", "#6C6C73")};
            }}
        """)

        main_layout = QVBoxLayout(dlg)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)
        main_layout.addWidget(tabs)

        # ── Cache refresh timer ────────────────────────────────────────────────
        _DOWNLOADED_SUFFIX = "  ✓ downloaded"

        def _refresh_cache_labels():
            _list_changed = False
            for i in range(rag_model_combo.count()):
                val  = rag_model_combo.itemData(i) or ""
                text = rag_model_combo.itemText(i)
                if _DOWNLOADED_SUFFIX not in text and _is_cached(val, _emb_cache_map):
                    rag_model_combo.setItemText(i, text + _DOWNLOADED_SUFFIX)
                    _list_changed = True
            for i in range(rag_rerank_combo.count()):
                val  = rag_rerank_combo.itemData(i) or ""
                text = rag_rerank_combo.itemText(i)
                if _DOWNLOADED_SUFFIX not in text and _is_cached(val, _rnk_cache_map):
                    rag_rerank_combo.setItemText(i, text + _DOWNLOADED_SUFFIX)
                    _list_changed = True
            if _list_changed:
                _dl_list_populate()

        cache_refresh_timer = QTimer(dlg)
        cache_refresh_timer.setInterval(4000)
        cache_refresh_timer.timeout.connect(_refresh_cache_labels)

        try:
            c.register_widget("ai_settings_dialog",             dlg)
            c.register_widget("ai_settings_tabs",               tabs)
            c.register_widget("ai_settings_llm_cli_edit",       llm_cli_edit)
            c.register_widget("ai_settings_llm_web_chat_edit",  llm_web_chat_edit)
            c.register_widget("ai_settings_logs_terminal_edit", logs_terminal_edit)
            c.register_widget("ai_settings_agent_role_combo",   settings_agent_role_combo)
            c.register_widget("ai_settings_skills_combo",       settings_skills_combo)
            c.register_widget("settings_goal_combo",            settings_goal_combo)
            c.register_widget("ai_settings_rag_model_combo",    rag_model_combo)
            c.register_widget("ai_settings_rag_rerank_combo",   rag_rerank_combo)
            c.register_widget("ai_settings_memory_list",        memory_list)
            c.register_widget("ai_settings_cache_timer",        cache_refresh_timer)
        except Exception:
            pass

    def create_author_dialog():
        author_dialog = QDialog()
        author_dialog.setWindowTitle("Author")
        author_dialog.setModal(True)
        layout = QVBoxLayout()
        author_label = QLabel("""
        <div style="text-align: center; padding: 16px;">
            <b style="font-size: 15px;">PurrSh3ll</b><br>
            <span style="color: gray;">AI-powered terminal environment for pentesters</span><br><br>

            <b>Damian Ząbek</b><br>
            Cybersecurity Specialist<br><br>

            <table cellspacing="8" style="margin: 0 auto;">
                <tr>
                    <td>🐱&nbsp;<b>GitHub</b></td>
                    <td><a href="https://github.com/PurrSh3ll/purrsh3ll">github.com/PurrSh3ll/purrsh3ll</a></td>
                </tr>
                <tr>
                    <td>💼&nbsp;<b>LinkedIn</b></td>
                    <td><a href="https://www.linkedin.com/in/damian-ząbek-905518364/">linkedin.com/in/damian-ząbek</a></td>
                </tr>
                <tr>
                    <td>📧&nbsp;<b>Email</b></td>
                    <td><a href="mailto:purrsh3ll@gmail.com">purrsh3ll@gmail.com</a></td>
                </tr>
                <tr>
                    <td>▶️&nbsp;<b>Demo</b></td>
                    <td><a href="https://youtu.be/kpUUVxBdFqE">youtu.be/kpUUVxBdFqE</a></td>
                </tr>
            </table><br>

            <span style="color: gray; font-size: 11px;">Released under the GNU General Public License v3.0</span>
        </div>
        """)
        author_label.setTextFormat(Qt.TextFormat.RichText)
        author_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        author_label.setOpenExternalLinks(True)
        author_label.setWordWrap(True)
        layout.addWidget(author_label)
        author_dialog.setLayout(layout)
        author_dialog.resize(420, 300)
        try:
            c.register_widget("author_dialog", author_dialog)
        except Exception:
            pass

    create_settings_dialog()
    create_ai_settings_dialog()
    create_licenses_dialog()
    create_author_dialog()

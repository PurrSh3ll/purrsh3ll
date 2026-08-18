# PurrSh3ll — AI/app settings dialog builder (general settings)
# Copyright (C) 2024-2025  PurrSh3ll Contributors
#
# Dialog builder extracted verbatim from menu_builder.build_menu so that huge
# function stops being a monolith. Behaviour-preserving: same body, same widget
# registrations via the controller; main_window is now an explicit parameter
# instead of a closure capture.

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
c = controller_instance


def create_settings_dialog(main_window):
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

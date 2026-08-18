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
from gui.builders.settings_dialog import create_settings_dialog
from gui.builders.licenses_dialog import create_licenses_dialog
from gui.builders.ai_settings_dialog import create_ai_settings_dialog
from gui.builders.author_dialog import create_author_dialog

logger = logging.getLogger(__name__)




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

    # create_settings_dialog → settings_dialog.py (imported at top).

    # create_licenses_dialog → licenses_dialog.py (imported at top).

    # create_ai_settings_dialog → ai_settings_dialog.py (imported at top).

    # create_author_dialog → author_dialog.py (imported at top).

    create_settings_dialog(main_window)
    create_ai_settings_dialog(main_window)
    create_licenses_dialog()
    create_author_dialog()

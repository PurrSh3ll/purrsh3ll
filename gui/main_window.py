import logging

from PyQt6.QtWidgets import QMainWindow, QApplication, QMenu, QMessageBox, QDialog, QLabel, QVBoxLayout, QInputDialog
from PyQt6.QtCore import QTimer, Qt

logger = logging.getLogger(__name__)
from core.controller import controller_instance
from gui.ui_factory import create_main_widget, set_ui, create_menu
from gui.filters import GlobalFilter
from gui.watchers.module_loader import WatcherThread
from functools import partial
import os
import subprocess
import shutil
import keyring
from core.constants import KEYRING_SERVICE

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.c = controller_instance

        self._setup_window()
        self._build_ui()
        self._connect_menu()
        self._setup_tree()
        self._connect_buttons()
        self._start_watchers()
        self._load_state()
        self._install_filters()

    def _setup_window(self):
        self.setWindowTitle("PurrSh3ll v.1.0.0 — Early Access")
        self.setGeometry(self.c.start_x, self.c.start_y, self.c.width, self.c.height)
        self.c.register_widget("main_window", self)
        self.c.SERVICE = KEYRING_SERVICE
        self.c.USER = os.getenv("USER") or os.getlogin()
        self._resize_timer = QTimer(self)
        self._resize_timer.setSingleShot(True)
        self._resize_timer.setInterval(30)
        self._resize_timer.timeout.connect(self._on_resize_settled)

    def _build_ui(self):
        create_main_widget(self)
        self.setCentralWidget(self.c.get_widget("central_widget"))
        self.c.load_themes()
        set_ui(self)
        self.c.set_terminal()
        create_menu(self)
        self.c.change_actual_theme(None)

    def _connect_menu(self):
        self.c.get_widget("command_palette_action").triggered.connect(self.c.open_command_palette)
        self.c.get_widget("open_file_action").triggered.connect(self._on_open_file)
        self.c.get_widget("exit_action").triggered.connect(self.close)
        self.c.get_widget("settings_action").triggered.connect(self.c.open_settings)
        self.c.get_widget("ai_settings_action").triggered.connect(self.c.open_ai_settings)
        self.c.get_widget("about_qterm_action").triggered.connect(self.c.open_qterm_help)
        self.c.get_widget("about_qt_action").triggered.connect(self.c.open_qt_help)
        self.c.get_widget("about_licenses_action").triggered.connect(self.c.open_licenses_help)
        self.c.get_widget("author_action").triggered.connect(self.c.open_author_dialog)
        self.c.get_widget("whats_new_action").triggered.connect(self._show_coming_soon)
        self.c.get_widget("check_updates_action").triggered.connect(self._show_coming_soon)
        self.c.get_widget("user_guide_action").triggered.connect(
            lambda: self.c.open_new_tab_for_terminal(file=self.c.user_guide_path))
        self.c.get_widget("manual_action").triggered.connect(
            lambda: self.c.open_new_tab_for_terminal(file=self.c.manual_path))
        for theme_name in self.c.themes:
            self.c.get_widget(f"{theme_name}_theme").triggered.connect(
                lambda checked, t=theme_name: self.c.change_actual_theme(t))

    def _show_coming_soon(self):
        msg = QMessageBox(self)
        msg.setWindowTitle("Coming Soon")
        msg.setText("This feature will be available in an upcoming version.")
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.setStyleSheet(self.c.messagebox_stylesheet)
        msg.exec()

    def _on_open_file(self):
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(self, "Open File", os.path.expanduser("~"))
        if path:
            self.c.open_new_tab_for_terminal(file=path)

    def _setup_tree(self):
        self.c.update_modules()

        tree = self.c.widgets["tree"]
        self.c.widgets["search_box"].textChanged.connect(self.c.filter_tree)

        tree.itemExpanded.connect(self.c.on_item_expand)
        tree.itemCollapsed.connect(self.c.on_item_expand)
        tree.itemDoubleClicked.connect(self.c.open_new_tab_for_tree)

        tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        tree.customContextMenuRequested.connect(self._on_tree_context_menu)

    def _on_tree_context_menu(self, pos):
        tree = self.c.widgets["tree"]
        item = tree.itemAt(pos)

        # Click on empty space — show New menu rooted at usermodules
        if item is None or item.data(0, Qt.ItemDataRole.UserRole) == "__separator__":
            menu = QMenu(tree)
            try:
                menu.setStyleSheet(self.c.__class__.menu_stylesheet)
            except Exception:
                pass
            new_menu        = menu.addMenu("New")
            new_file_action = new_menu.addAction("File")
            new_dir_action  = new_menu.addAction("Directory")
            action = menu.exec(tree.viewport().mapToGlobal(pos))
            if action in (new_file_action, new_dir_action):
                self._create_new(self.c.user_modules_path, is_file=(action == new_file_action))
            return

        path = item.data(0, Qt.ItemDataRole.UserRole)
        is_top_appmodule = (
            path and
            path.startswith(self.c.app_modules_path) and
            os.path.dirname(os.path.normpath(path)) == os.path.normpath(self.c.app_modules_path)
        )
        menu = QMenu(tree)
        try:
            menu.setStyleSheet(self.c.__class__.menu_stylesheet)
        except Exception:
            pass
        open_action      = menu.addAction("Open in Default Application")
        copy_path_action = menu.addAction("Copy Path")
        new_menu        = menu.addMenu("New")
        new_file_action = new_menu.addAction("File")
        new_dir_action  = new_menu.addAction("Directory")

        if not is_top_appmodule:
            rename_action   = menu.addAction("Rename")
            menu.addSeparator()
            delete_action   = menu.addAction("Delete")

        action = menu.exec(tree.viewport().mapToGlobal(pos))

        if action == open_action:
            if path:
                subprocess.Popen(["xdg-open", path])
        elif action == copy_path_action:
            if path:
                QApplication.clipboard().setText(path)
        elif action in (new_file_action, new_dir_action):
            self._create_new(path, is_file=(action == new_file_action))
        elif not is_top_appmodule:
            if action == rename_action:
                self._rename_path(path)
            elif action == delete_action:
                self._delete_path(path)

    def _rename_path(self, path):
        new_name, ok = QInputDialog.getText(self, "Rename", "Enter new name:", text=os.path.basename(path))
        if not (ok and new_name.strip()):
            return
        new_path = os.path.join(os.path.dirname(path), new_name.strip())
        if os.path.exists(new_path):
            QMessageBox.warning(self, "Rename Failed", f'"{new_name}" already exists in this location.')
        else:
            try:
                os.rename(path, new_path)
            except Exception as e:
                QMessageBox.critical(self, "Rename Failed", str(e))

    def _create_new(self, path, is_file):
        base_dir = path if os.path.isdir(path) else os.path.dirname(path)
        label = "file" if is_file else "directory"
        new_name, ok = QInputDialog.getText(self, f"New {label.capitalize()}", f"Enter {label} name:")
        if not (ok and new_name.strip()):
            return
        new_path = os.path.join(base_dir, new_name.strip())
        if os.path.exists(new_path):
            QMessageBox.warning(self, f"New {label.capitalize()} Failed", f'"{new_name}" already exists in this location.')
        else:
            try:
                open(new_path, "x").close() if is_file else os.makedirs(new_path)
            except Exception as e:
                QMessageBox.critical(self, f"New {label.capitalize()} Failed", str(e))

    def _delete_path(self, path):
        name = os.path.basename(path)
        reply = QMessageBox.question(
            self, "Confirm Delete", f'Are you sure you want to delete "{name}"?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
            except Exception as e:
                QMessageBox.critical(self, "Delete Failed", str(e))

    def _connect_buttons(self):
        self.c.get_widget("menu_button").clicked.connect(self.c.toggle_menu)
        self.c.get_widget("slide_button").clicked.connect(partial(self.c.toggle_slide, "slide_button"))
        self.c.get_widget("mode_button").clicked.connect(partial(self.c.toggle_mode, "mode_button"))
        self.c.get_widget("notes_button").clicked.connect(partial(self.c.toggle_notes, "notes_button"))
        self.c.get_widget("chat_button").clicked.connect(partial(self.c.toggle_chat, "chat_button"))
        self.c.get_widget("snippet_button").clicked.connect(partial(self.c.toggle_snippets, "snippet_button"))
        self.c.get_widget("panel_slide_add_btn").clicked.connect(self.c.add_observer_var)
        self.c.get_widget("panel_options_btn").clicked.connect(self.c.open_slide_panel_options)
        self.c.get_widget("panel_del_all_rows_btn").clicked.connect(self._confirm_delete_all_rows)

    def _confirm_delete_all_rows(self):
        reply = QMessageBox.question(
            self, "Confirm Delete", "Are you sure you want to remove all variables?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.c.delete_all_observer_rows()

    def _start_watchers(self):
        self.watcher_thread = WatcherThread([
            self.c.app_modules_path,
            self.c.user_modules_path,
        ])
        self.watcher_thread.file_changed.connect(self.c.schedule_update_modules)
        self.watcher_thread.start()

        try:
            import json
            with open(self.c.config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            if cfg.get("rag", {}).get("auto_index", False):
                self.c.start_rag_watcher()
        except Exception:
            pass

    def _load_state(self):
        self.c.load_dynamic_variables()
        self.c.load_sys_vars()

    def _install_filters(self):
        self.filter = GlobalFilter()
        QApplication.instance().installEventFilter(self.filter)
        QTimer.singleShot(0, self.c.center_welcome_text)
        QTimer.singleShot(0, self.c.set_position_active_profile_combo)
        QTimer.singleShot(0, self.c.restore_session)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._resize_timer.start()

    def _on_resize_settled(self):
        self.c.center_welcome_text()
        self.c.set_position_slide_panel()
        self.c.set_position_mode_panel()
        self.c.set_position_slide_button()
        self.c.set_position_mode_button()
        self.c.set_position_notes_panel()
        self.c.set_position_notes_button()
        self.c.set_position_chat_panel()
        self.c.set_position_chat_button()
        self.c.set_position_snippet_panel()
        self.c.set_position_snippet_button()
        self.c.update_dropdown_visibility()
        self.c.update_dropdown_terminals()
        self.c.set_position_active_profile_combo()

    def closeEvent(self, event):
        msg = QMessageBox(self)
        msg.setWindowTitle("Confirm exit")
        msg.setText("Are you sure you want to quit?")
        msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        msg.setDefaultButton(QMessageBox.StandardButton.No)
        msg.setStyleSheet(self.c.messagebox_stylesheet)

        if msg.exec() != QMessageBox.StandardButton.Yes:
            event.ignore()
            return

        self._show_shutdown_dialog()
        self._save_state_on_close()
        self._stop_watchers()
        self._cleanup_on_close()
        event.accept()

    def _show_shutdown_dialog(self):
        dlg = QDialog(self, Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        dlg.setModal(False)
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(24, 16, 24, 16)
        label = QLabel("Application is shutting down, please wait...")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)
        dlg.setStyleSheet(self.c.messagebox_stylesheet)
        dlg.adjustSize()
        dlg.show()
        QApplication.processEvents()

    def _save_state_on_close(self):
        try:
            self.c.widgets["op_rows_panel"].save_state_to_file()
        except Exception:
            pass
        self.c.save_session()

    def _stop_watchers(self):
        self.watcher_thread.requestInterruption()
        self.c.watchdog.stop()
        self.c.watchdog.wait(3000)
        self.c.stop_rag_watcher()
        if self.c.orphan_cleaner.isRunning():
            self.c.orphan_cleaner.wait(2000)

    def _cleanup_on_close(self):
        app = QApplication.instance()
        if app is not None:
            app.removeEventFilter(self.filter)

        try:
            # Use the SecretService backend directly to avoid fallback backends
            # that may open GUI dialogs when D-Bus is disconnecting on shutdown.
            from keyring.backends.SecretService import Keyring as _SSKeyring
            pw = _SSKeyring().get_password(self.c.SERVICE, self.c.USER)
            if pw:
                result = subprocess.run(
                    ["sudo", "-S", "--", "docker", "rm", "-f", "webmap"],
                    input=pw + "\n",
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    logger.warning(
                        "docker rm -f webmap exited with code %d: %s",
                        result.returncode, result.stderr.strip()
                    )
        except Exception:
            logger.debug("Skipping Docker webmap cleanup — keyring unavailable at shutdown")

        try:
            keyring.delete_password(self.c.SERVICE, self.c.USER)
        except Exception:
            pass

        if getattr(self.c, "delete_logs_at_close", True):
            log_path = os.path.join(self.c.base_path, "appdata", "logs", "terminal_history.jsonl")
            try:
                if os.path.exists(log_path):
                    os.remove(log_path)
            except Exception as e:
                pass

        if getattr(self.c, "delete_notes_at_close", False):
            notes_path = os.path.join(self.c.base_path, "appdata", "psnotes.txt")
            try:
                if os.path.exists(notes_path):
                    open(notes_path, "w").close()
            except Exception as e:
                pass

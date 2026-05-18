from PyQt6.QtWidgets import (
    QSplitter, QGroupBox, QHBoxLayout, QVBoxLayout, QWidget,
    QLabel, QPushButton, QDialog, QToolButton, QMenu, QSizePolicy,
    QTextEdit, QDialogButtonBox, QFileDialog, QComboBox, QMessageBox,
)
from PyQt6.QtGui import QPixmap, QMovie
from PyQt6.QtCore import QSize, Qt
import os
import json

from core.controller import controller_instance
from gui.widgets.custom_tab_widget import CustomTabWidget
from gui.widgets.custom_line_edit import ExpandingLineEdit
from gui.widgets.term_tab_bar import MyTabWidget
from gui.dialogs.custom_dialog import CustomDialog

c = controller_instance

def build_main_layout(main_window):

    def create_main_window_splitters():
        central_widget = c.widgets["central_widget"]
        central_layout = QVBoxLayout(central_widget)
        h_splitter_top = QSplitter(Qt.Orientation.Horizontal, parent=central_widget)
        v_splitter_bottom = QSplitter(Qt.Orientation.Horizontal, parent=central_widget)
        splitter_main = QSplitter(Qt.Orientation.Vertical, parent=central_widget)
        central_layout.addWidget(splitter_main)
        c.register_widget("central_layout", central_layout)
        c.register_widget("splitter_main", splitter_main)
        c.register_widget("h_splitter_top", h_splitter_top)
        c.register_widget("v_splitter_bottom", v_splitter_bottom)

    def create_scripts_listbox():
        central_widget = c.widgets["central_widget"]
        scripts_groupbox = QGroupBox(parent=central_widget)
        scripts_layout = QVBoxLayout(scripts_groupbox)
        search_container = QHBoxLayout()
        search_icon = QLabel("🔍", scripts_groupbox)
        search_icon.setStyleSheet("font-size: 16px;")
        search_icon.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        search_box = ExpandingLineEdit(parent=scripts_groupbox)
        search_box.setPlaceholderText("Search...")
        search_container.addWidget(search_icon)
        search_container.addWidget(search_box)
        scripts_layout.addLayout(search_container)
        from gui.widgets.file_tree_widget import FileTreeWidget
        tree = FileTreeWidget(parent=scripts_groupbox)
        tree.header().setVisible(False)
        scripts_layout.addWidget(tree)
        c.register_widget("search_box", search_box)
        c.register_widget("search_icon", search_icon)
        c.register_widget("tree", tree)
        c.register_widget("scripts_layout", scripts_layout)
        c.register_widget("scripts_groupbox", scripts_groupbox)

    def create_execution_window():
        central_widget = c.widgets["central_widget"]
        execution_groupbox = QGroupBox(parent=central_widget)
        execution_layout = QVBoxLayout(execution_groupbox)
        execution_tabs = CustomTabWidget(parent=execution_groupbox)
        execution_layout.addWidget(execution_tabs)
        c.register_widget("execution_groupbox", execution_groupbox)
        c.register_widget("execution_layout", execution_layout)
        c.register_widget("execution_tabs", execution_tabs)

    def create_terminal():
        central_widget = c.widgets["central_widget"]
        terminal_groupbox = QGroupBox(parent=central_widget)
        terminal_layout = QVBoxLayout(terminal_groupbox)
        terminal_tabs = MyTabWidget(parent=terminal_groupbox)
        terminal_tabs.setMovable(True)
        terminal_tabs.setTabsClosable(True)
        c.register_widget("terminal_groupbox", terminal_groupbox)
        c.register_widget("terminal_layout", terminal_layout)
        c.register_widget("terminal_tabs", terminal_tabs)

    def dropdown_terminal_button():
        dropdown_button = QToolButton()
        dropdown_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        dropdown_menu = QMenu()
        dropdown_button.setMenu(dropdown_menu)
        dropdown_button.setArrowType(Qt.ArrowType.DownArrow)
        dropdown_button.setStyleSheet("QToolButton::menu-indicator { image: none; }")
        dropdown_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        dropdown_button.setFixedHeight(24)
        dropdown_button.setFixedWidth(18)
        dropdown_button.hide()
        c.register_widget("dropdown_terminal_button", dropdown_button)
        c.register_widget("dropdown_terminal_menu", dropdown_menu)

    def create_change_theme_limit_dial():
        dialog = QDialog(main_window, Qt.WindowType.FramelessWindowHint)
        dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
        message = (
            "<div style='text-align: center; font-size: 16px;'>"
            "⚠️  Can't change theme<br>"
            "<span style='font-size: 14px;'>Please close some tabs — more than 30 are open.</span>"
            "</div>"
        )
        label = QLabel(message)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setTextFormat(Qt.TextFormat.RichText)
        ok_btn = QPushButton("OK")
        ok_btn.setFixedHeight(28)
        ok_btn.setDefault(True)
        ok_btn.clicked.connect(dialog.close)
        body_layout = QVBoxLayout()
        body_layout.addWidget(label)
        body_layout.addSpacing(10)
        btn_layout = QHBoxLayout()
        btn_layout.addStretch(1)
        btn_layout.addWidget(ok_btn)
        btn_layout.addStretch(1)
        body_layout.addLayout(btn_layout)
        body_layout.setContentsMargins(18, 14, 18, 14)
        dialog.setLayout(body_layout)
        dialog.adjustSize()
        dialog.setFixedSize(dialog.sizeHint())
        c.register_widget("theme_limit_dialog", dialog)

    def create_change_theme_info():
        dialog = QDialog(main_window, Qt.WindowType.FramelessWindowHint)
        dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
        message = (
            "<div style='text-align: center; font-size: 16px;'>"
            "⏳  Applying new theme...<br>"
            "<span style='font-size: 14px;'>Please wait</span>"
            "</div>"
        )
        label = QLabel(message)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setTextFormat(Qt.TextFormat.RichText)
        layout = QVBoxLayout(dialog)
        layout.addWidget(label)
        layout.setContentsMargins(25, 20, 25, 20)
        dialog.setLayout(layout)
        dialog.adjustSize()
        dialog.setFixedSize(dialog.sizeHint())
        c.register_widget("theme_dial_info", dialog)

    def create_slider_button():
        slide_button = QPushButton("👁️", c.widgets["central_widget"])
        slide_button.setFixedWidth(20)
        slide_button.setFixedHeight(50)
        c.register_widget("slide_button", slide_button)

    def create_chat_button():
        chat_button = QPushButton("🤖", c.widgets["central_widget"])
        chat_button.setFixedWidth(20)
        chat_button.setFixedHeight(50)
        c.register_widget("chat_button", chat_button)

    def create_notes_button():
        notes_button = QPushButton("📝", c.widgets["central_widget"])
        notes_button.setFixedWidth(20)
        notes_button.setFixedHeight(50)
        c.register_widget("notes_button", notes_button)

    def create_mode_button():
        mode_button = QPushButton("🔧", c.widgets["central_widget"])
        mode_button.setFixedWidth(20)
        mode_button.setFixedHeight(50)
        c.register_widget("mode_button", mode_button)

    def create_snippet_button():
        snippet_button = QPushButton("✂️", c.widgets["central_widget"])
        snippet_button.setFixedWidth(20)
        snippet_button.setFixedHeight(50)
        c.register_widget("snippet_button", snippet_button)

    def create_welcome_text():
        _DEFAULT_WELCOME = (
            "<p><b style='font-size:18px;'>Welcome to PurrSh3ll</b></p>"
            "<p>H3llo Damian, who would you like to hack today?</p>"
        )

        def _load_welcome_text():
            try:
                with open(c.config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                saved = cfg.get("welcome", {}).get("custom_text", "")
                return saved if saved else _DEFAULT_WELCOME
            except Exception:
                return _DEFAULT_WELCOME

        def _save_welcome_text(text):
            try:
                cfg = {}
                if os.path.exists(c.config_path):
                    with open(c.config_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                cfg.setdefault("welcome", {})["custom_text"] = text
                with open(c.config_path, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
            except Exception:
                pass

        def _on_welcome_double_click():
            dlg = QDialog(c.widgets["main_window"])
            dlg.setWindowTitle("Edit welcome text")
            dlg.setModal(True)
            dlg.resize(420, 200)
            layout = QVBoxLayout(dlg)
            layout.setContentsMargins(12, 12, 12, 12)
            layout.setSpacing(8)
            editor = QTextEdit(dlg)
            editor.setPlainText(welcome_label.text() if not welcome_label.text().startswith("<") else
                                welcome_label.text().replace("<p>", "").replace("</p>", "\n")
                                .replace("<b style='font-size:18px;'>", "").replace("</b>", "")
                                .strip())
            editor.setAcceptRichText(False)
            layout.addWidget(editor)
            buttons = QDialogButtonBox(
                QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, dlg
            )
            layout.addWidget(buttons)
            try:
                dlg.setStyleSheet(c.messagebox_stylesheet)
            except Exception:
                pass
            buttons.accepted.connect(dlg.accept)
            buttons.rejected.connect(dlg.reject)
            if dlg.exec() == QDialog.DialogCode.Accepted:
                raw = editor.toPlainText().strip()
                lines = raw.splitlines()
                if lines:
                    html = f"<p><b style='font-size:18px;'>{lines[0]}</b></p>"
                    for line in lines[1:]:
                        html += f"<p>{line}</p>" if line.strip() else "<p>&nbsp;</p>"
                else:
                    html = _DEFAULT_WELCOME
                welcome_label.setText(html)
                _save_welcome_text(html)

        _DEFAULT_IMAGE_PATH = os.path.join(c.base_path, "icons", "test_5.gif")

        def _load_image_path():
            try:
                with open(c.config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                saved = cfg.get("welcome", {}).get("image_path", "")
                return saved if saved and os.path.exists(saved) else _DEFAULT_IMAGE_PATH
            except Exception:
                return _DEFAULT_IMAGE_PATH

        def _save_image_path(path):
            try:
                cfg = {}
                if os.path.exists(c.config_path):
                    with open(c.config_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                cfg.setdefault("welcome", {})["image_path"] = path
                with open(c.config_path, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
            except Exception:
                pass

        _current_movie = [None]

        def _apply_image(path, label):
            if path.lower().endswith(".gif"):
                if _current_movie[0] is not None:
                    _current_movie[0].stop()
                label.setPixmap(QPixmap())
                m = QMovie(path)
                label.setMovie(m)
                m.start()
                _current_movie[0] = m
                c.register_widget("movie", m)
            else:
                if _current_movie[0] is not None:
                    _current_movie[0].stop()
                    _current_movie[0] = None
                label.setMovie(None)
                px = QPixmap(path)
                if not px.isNull():
                    label.setPixmap(px)

        def _on_gif_double_click():
            dlg = QDialog(c.widgets["main_window"])
            dlg.setWindowTitle("Welcome image")
            dlg.setModal(True)
            dlg.resize(300, 120)
            layout = QVBoxLayout(dlg)
            layout.setContentsMargins(16, 16, 16, 16)
            layout.setSpacing(10)
            try:
                dlg.setStyleSheet(c.messagebox_stylesheet)
            except Exception:
                pass
            btn_choose  = QPushButton("Choose image...", dlg)
            btn_default = QPushButton("Set default image", dlg)
            btn_cancel  = QPushButton("Cancel", dlg)
            layout.addWidget(btn_choose)
            layout.addWidget(btn_default)
            layout.addWidget(btn_cancel)

            def _choose():
                path, _ = QFileDialog.getOpenFileName(
                    dlg, "Select image",
                    os.path.expanduser("~"),
                    "Images (*.gif *.png *.jpg *.jpeg *.bmp *.webp)"
                )
                if path:
                    _apply_image(path, gif_label)
                    _save_image_path(path)
                dlg.accept()

            def _set_default():
                _apply_image(_DEFAULT_IMAGE_PATH, gif_label)
                _save_image_path("")
                dlg.accept()

            btn_choose.clicked.connect(_choose)
            btn_default.clicked.connect(_set_default)
            btn_cancel.clicked.connect(dlg.reject)
            dlg.exec()

        class _WelcomeLabel(QLabel):
            def mouseDoubleClickEvent(self_, event):
                _on_welcome_double_click()

        class _GifLabel(QLabel):
            def mouseDoubleClickEvent(self_, event):
                _on_gif_double_click()

        container = QWidget(c.widgets["execution_tabs"])
        welcome_text_layout = QVBoxLayout(container)
        welcome_label = _WelcomeLabel()
        welcome_label.setText(_load_welcome_text())
        welcome_label.setStyleSheet("font-size: 14px;")
        welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome_label.setToolTip("Double-click to edit")
        gif_label = _GifLabel()
        gif_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gif_label.setToolTip("Double-click to change image")
        _apply_image(_load_image_path(), gif_label)
        welcome_text_layout.addWidget(welcome_label)
        welcome_text_layout.addWidget(gif_label)
        c.register_widget("welcome_label", welcome_label)
        c.register_widget("welcome_text_layout", welcome_text_layout)
        c.register_widget("welcome_tab_text", container)
        c.register_widget("gif_label", gif_label)

    def create_voice_button():
        central_widget = c.widgets["central_widget"]
        btn = QPushButton("🎙", central_widget)
        btn.setFixedSize(26, 22)
        btn.setToolTip("Voice command mode")
        btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        btn.setCheckable(True)
        btn.setChecked(False)

        _STYLE_OFF = (
            "QPushButton { background: transparent; border: 1px solid #555; "
            "border-radius: 3px; font-size: 13px; color: #aaa; }"
            "QPushButton:hover { border-color: #888; color: #fff; }"
        )
        _STYLE_ON = (
            "QPushButton { background: #6a1a1a; border: 1px solid #e05555; "
            "border-radius: 3px; font-size: 13px; color: #ff8888; }"
            "QPushButton:hover { background: #7a2020; }"
        )
        btn.setStyleSheet(_STYLE_OFF)

        def _on_clicked(checked):
            if not checked:
                btn.setStyleSheet(_STYLE_OFF)
                btn.setToolTip("Voice command mode")
                return

            # Show confirmation popup before activating
            msg = QMessageBox(c.widgets["main_window"])
            msg.setWindowTitle("Activate Voice Command Mode")
            msg.setIcon(QMessageBox.Icon.Question)
            msg.setText("<b>Activate Voice Command Mode?</b>")
            msg.setInformativeText(
                "Voice Command Mode will:\n\n"
                "• Access your <b>microphone continuously</b> in the background\n"
                "• Listen for a wake word to start recording\n"
                "• Send your speech to the active AI profile\n"
                "• Paste the generated command into the active terminal\n\n"
                "<i>You will be asked to confirm (Accept / Cancel) before any "
                "command is executed.</i>\n\n"
                "Make sure a vision/speech-capable profile is active.\n"
                "You can deactivate at any time by clicking the button again."
            )
            msg.setStandardButtons(
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel
            )
            msg.setDefaultButton(QMessageBox.StandardButton.Cancel)

            result = msg.exec()
            if result == QMessageBox.StandardButton.Ok:
                btn.setStyleSheet(_STYLE_ON)
                btn.setToolTip("Voice command mode: ACTIVE — click to deactivate")
            else:
                # User cancelled — revert toggle
                btn.blockSignals(True)
                btn.setChecked(False)
                btn.blockSignals(False)
                btn.setStyleSheet(_STYLE_OFF)

        btn.clicked.connect(_on_clicked)
        c.register_widget("voice_button", btn)

    def create_active_profile_combo():
        central_widget = c.widgets["central_widget"]
        combo = QComboBox(central_widget)
        combo.setFixedHeight(22)
        combo.setFixedWidth(170)
        combo.setToolTip("Active API profile")
        combo.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        def _reload(keep=None):
            combo.blockSignals(True)
            combo.clear()
            combo.addItem("— none —", "")
            try:
                with open(c.config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                prov = cfg.get("api_providers", {})
                active = keep if keep is not None else prov.get("active", "")
                for p in prov.get("profiles", []):
                    combo.addItem(p["name"], p["name"])
                idx = combo.findData(active)
                combo.setCurrentIndex(max(0, idx))
            except Exception:
                pass
            combo.blockSignals(False)

        def _on_changed():
            name = combo.currentData() or ""
            # save to config
            try:
                with open(c.config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                cfg.setdefault("api_providers", {})["active"] = name
                with open(c.config_path, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
            except Exception:
                pass
            # sync AI Settings combo if open
            ai_combo = c.widgets.get("ai_active_profile_combo")
            if ai_combo is not None:
                ai_combo.blockSignals(True)
                idx = ai_combo.findText(name if name else "— none —")
                if idx >= 0:
                    ai_combo.setCurrentIndex(idx)
                ai_combo.blockSignals(False)

        _reload()
        combo.currentIndexChanged.connect(_on_changed)
        c.register_widget("global_active_profile_combo", combo)
        c.register_widget("global_active_profile_combo_reload", _reload)

    def dropdown_menu_button():
        dropdown_button = QToolButton()
        dropdown_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        dropdown_menu = QMenu()
        dropdown_button.setMenu(dropdown_menu)
        dropdown_button.setArrowType(Qt.ArrowType.DownArrow)
        dropdown_button.setIconSize(QSize(22, 28))
        dropdown_button.setFixedHeight(24)
        dropdown_button.setFixedWidth(18)
        dropdown_button.hide()
        c.widgets["execution_tabs"].setCornerWidget(dropdown_button)
        c.register_widget("dropdown_button", dropdown_button)
        c.register_widget("dropdown_menu", dropdown_menu)

    def add_widgets_to_layout_and_setup():
        c.widgets["splitter_main"].addWidget(c.widgets["h_splitter_top"])
        c.widgets["splitter_main"].addWidget(c.widgets["v_splitter_bottom"])
        c.widgets["h_splitter_top"].addWidget(c.widgets["scripts_groupbox"])
        c.widgets["h_splitter_top"].addWidget(c.widgets["execution_groupbox"])
        c.widgets["v_splitter_bottom"].addWidget(c.widgets["terminal_groupbox"])
        c.widgets["h_splitter_top"].setSizes([100, 400])
        c.widgets["v_splitter_bottom"].setSizes([400, 400])
        c.widgets["splitter_main"].setSizes([400, 160])

    create_main_window_splitters()
    create_scripts_listbox()
    create_execution_window()
    dropdown_terminal_button()
    create_terminal()
    create_welcome_text()
    create_change_theme_limit_dial()
    create_change_theme_info()
    create_slider_button()
    create_chat_button()
    create_notes_button()
    create_mode_button()
    create_snippet_button()
    create_active_profile_combo()
    create_voice_button()
    dropdown_menu_button()
    add_widgets_to_layout_and_setup()

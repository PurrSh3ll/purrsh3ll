from gui.widgets.observable_panel import ObserverPanel
from PyQt6.QtWidgets import QApplication, QWidget, QLineEdit, QToolButton, QPushButton
from PyQt6.QtCore import QTimer
from PyQt6.sip import isdeleted

from core.stylesheets.base_styles import build_base_styles
from core.stylesheets.panel_styles import build_panel_styles
from core.stylesheets.terminal_styles import build_terminal_styles

def change_theme(controller):
    c = controller
    app = QApplication.instance()
    theme = getattr(c, "actual_theme", {})

    menu_bar = c.widgets.get("menu_bar")
    menu_button = c.widgets.get("menu_button")
    main_window = c.widgets.get("main_window")
    splitter_main = c.widgets.get("splitter_main")
    h_splitter_top = c.widgets.get("h_splitter_top")
    v_splitter_bottom = c.widgets.get("v_splitter_bottom")
    search_box = c.widgets.get("search_box")
    tree = c.widgets.get("tree")
    scripts_groupbox = c.widgets.get("scripts_groupbox")
    execution_groupbox = c.widgets.get("execution_groupbox")
    execution_tabs = c.widgets.get("execution_tabs")
    terminal_groupbox = c.widgets.get("terminal_groupbox")
    terminal_tabs = c.widgets.get("terminal_tabs")
    slide_button = c.widgets.get("slide_button")
    chat_button = c.widgets.get("chat_button")
    notes_button = c.widgets.get("notes_button")
    mode_button = c.widgets.get("mode_button")
    welcome_label = c.widgets.get("welcome_label")
    theme_limit_dialog = c.widgets.get("theme_limit_dialog")
    theme_dial_info = c.widgets.get("theme_dial_info")
    chat_panel = c.widgets.get("chat_panel")
    chat_future_label = c.widgets.get("chat_future_label")
    chat_combo_interface = c.widgets.get("chat_combo_interface")
    chat_combo_input = c.widgets.get("chat_combo_input")
    chat_combo_context = c.widgets.get("chat_combo_context")
    chat_btn_settings = c.widgets.get("chat_btn_settings")
    chat_btn_info = c.widgets.get("chat_btn_info")
    chat_btn_run = c.widgets.get("chat_btn_run")
    chat_btn_run_menu = c.widgets.get("chat_btn_run_menu")
    chat_cmd_preview = c.widgets.get("chat_cmd_preview")
    chat_combo_custom = c.widgets.get("chat_combo_custom")
    chat_btn_add = c.widgets.get("chat_btn_add")
    chat_webui_dialog = c.widgets.get("chat_webui_dialog")
    op_rows_panel = c.widgets.get("op_rows_panel")
    slide_panel = c.widgets.get("slide_panel")
    panel_reload_btn = c.widgets.get("panel_reload_btn")
    panel_del_all_rows_btn = c.widgets.get("panel_del_all_rows_btn")
    panel_options_btn = c.widgets.get("panel_options_btn")
    panel_slide_add_btn = c.widgets.get("panel_slide_add_btn")
    mode_panel = c.widgets.get("mode_panel")
    mode_panel_scroll = c.widgets.get("mode_panel_scroll")
    panel_mode_content = c.widgets.get("panel_mode_content")
    panel_mode_add_btn = c.widgets.get("panel_mode_add_btn")
    mode_added_var_label = c.widgets.get("mode_added_var_label")
    notes_panel = c.widgets.get("notes_panel")
    notes_panel_scroll = c.widgets.get("notes_panel_scroll")
    notes_panel_content = c.widgets.get("notes_panel_content")
    notes_add_btn = c.widgets.get("notes_add_btn")
    notes_label = c.widgets.get("notes_label")
    notes_editor = c.widgets.get("notes_editor")
    snippet_panel = c.widgets.get("snippet_panel")
    snippet_widget = c.widgets.get("snippet_widget")
    snippet_button = c.widgets.get("snippet_button")
    dropdown_button = c.widgets.get("dropdown_button")
    dropdown_menu = c.widgets.get("dropdown_menu")
    slider_options_dialog = c.widgets.get("slider_options_dialog")
    dropdown_terminal_button = c.widgets.get("dropdown_terminal_button")
    dropdown_terminal_menu = c.widgets.get("dropdown_terminal_menu")
    btn_add_console = c.widgets.get("btn_add_console")
    btn_add_left = c.widgets.get("btn_add_left")
    btn_plus_menu = c.widgets.get("btn_plus_menu")
    settings_menu = c.widgets.get("settings_dialog")
    qterminal_dialog = c.widgets.get("qterminal_dialog")
    qt_dialog = c.widgets.get("qt_dialog")
    licenses_dialog = c.widgets.get("licenses_dialog")

    bg = theme.get("background", {})
    fg = theme.get("foreground", {})
    bd = theme.get("border", {})
    gl = theme.get("grid_line", {})
    terminal_color = theme.get("terminal", {})

    s = {}
    s.update(build_base_styles(bg, fg, bd, gl))
    s.update(build_panel_styles(bg, fg, bd))
    s.update(build_terminal_styles(bg, fg, bd))

    # Rozwiązanie 1: setUpdatesEnabled — blokuje ~50 pośrednich repaintów,
    # wykonuje jedno przerysowanie po zakończeniu bloku.
    main_window.setUpdatesEnabled(False)
    try:
        menu_bar.setStyleSheet(s["qss_QMenu"])
        menu_button.setStyleSheet(s["qss_QPushButton"])
        main_window.setStyleSheet(s["qss_QMainWindow"])
        splitter_main.setStyleSheet(s["qss_QSplitter"])
        h_splitter_top.setStyleSheet(s["qss_QSplitter"])
        v_splitter_bottom.setStyleSheet(s["qss_QSplitter"])
        search_box.setStyleSheet(s["qss_QLineEdit"])
        tree.setStyleSheet(s["qss_QTreeWidget"] + s["qss_QScrollArea"])

        theme_limit_dialog.setStyleSheet(s["qss_QDialog_global"])
        theme_dial_info.setStyleSheet(s["qss_QDialog_global"])

        scripts_groupbox.setStyleSheet(s["qss_QGroupBox"])
        execution_tabs.setStyleSheet(s["qss_QTabWidget"] + s["qss_QToolButton"] + s["qss_QMenu"])
        execution_groupbox.setStyleSheet(s["qss_QGroupBox"])
        terminal_groupbox.setStyleSheet(s["qss_QGroupBox"])
        terminal_tabs.setStyleSheet(s["qss_QTabWidget_terminal"] + s["qss_QToolButton"] + s["qss_QMenu"])

        if callable(getattr(c, 'refresh_terminal_paused_colors', None)):
            c.refresh_terminal_paused_colors()

        slide_button.setStyleSheet(s["qss_QPushButton"])
        chat_button.setStyleSheet(s["qss_QPushButton"])
        notes_button.setStyleSheet(s["qss_QPushButton"])
        mode_button.setStyleSheet(s["qss_QPushButton"])
        welcome_label.setStyleSheet(s["qss_QLabel_welcome"])

        chat_panel.setStyleSheet(s["qss_QFrame"])
        if chat_future_label:
            chat_future_label.setStyleSheet(s["qss_QLabel"])
        if chat_combo_interface:
            chat_combo_interface.setStyleSheet(s["qss_QComboBox"])
        if chat_combo_input:
            chat_combo_input.setStyleSheet(s["qss_QComboBox"])
        if chat_combo_context:
            chat_combo_context.setStyleSheet(s["qss_QComboBox"])
        if chat_btn_settings:
            chat_btn_settings.setStyleSheet(s["qss_QPushButton"])
        if chat_btn_info:
            chat_btn_info.setStyleSheet(s["qss_QPushButton"])
        if chat_btn_run:
            chat_btn_run.setStyleSheet(s["qss_QPushButton"])
        if chat_btn_run_menu:
            chat_btn_run_menu.setStyleSheet(s["qss_QMenu"])
        if chat_cmd_preview:
            chat_cmd_preview.setStyleSheet(s["qss_QPlainTextEdit_terminal"] + s["qss_QScrollArea"])
        if chat_combo_custom:
            chat_combo_custom.setStyleSheet(s["qss_QComboBox"])
        if chat_btn_add:
            chat_btn_add.setStyleSheet(s["qss_QPushButton"])
        chat_info_cmd_label = c.widgets.get("chat_info_cmd_label")
        if chat_info_cmd_label:
            chat_info_cmd_label.setStyleSheet(s["qss_QPlainTextEdit_terminal"] + s["qss_QScrollArea"])

        slide_panel.setStyleSheet(s["qss_QFrame"])
        op_rows_panel.setStyleSheet(s["qss_QWidget"])
        if panel_reload_btn:
            panel_reload_btn.setStyleSheet(s["qss_QPushButton"])
        panel_del_all_rows_btn.setStyleSheet(s["qss_QPushButton"])
        panel_options_btn.setStyleSheet(s["qss_QPushButton"])
        panel_slide_add_btn.setStyleSheet(s["qss_QPushButton"])

        mode_panel.setStyleSheet(s["qss_QFrame"])
        mode_panel_scroll.setStyleSheet(s["qss_QScrollArea"])
        panel_mode_content.setStyleSheet(s["qss_QWidget"])
        panel_mode_add_btn.setStyleSheet(s["qss_QPushButton"])
        mode_added_var_label.setStyleSheet(s["qss_QLabel"])

        notes_panel.setStyleSheet(s["qss_QFrame"])
        if notes_panel_scroll:
            notes_panel_scroll.setStyleSheet(s["qss_QScrollArea"])
        if notes_panel_content:
            notes_panel_content.setStyleSheet(s["qss_QWidget"])
        if notes_add_btn:
            notes_add_btn.setStyleSheet(s["qss_QPushButton"])
        if notes_label:
            notes_label.setStyleSheet(s["qss_QLabel"])
        if notes_editor:
            notes_editor.setStyleSheet(s["qss_QPlainTextEdit"])

        if snippet_panel:
            snippet_panel.setStyleSheet(s["qss_QFrame"])
        if snippet_widget:
            snippet_widget.setStyleSheet(
                s["qss_QWidget"] + s["qss_QLineEdit"] + s["qss_QPushButton"] +
                s["qss_QComboBox"] + s["qss_QScrollArea"] + s["qss_QLabel"] +
                f"""
                QLabel#snippet_preview {{ color: {fg.get("painter_text", "#AAAAAA")}; font-size: 10px; padding-left: 14px; }}
                QFrame#snippet_sep {{ color: {bd.get("default", "#555")}; }}
                """
            )
        if snippet_button:
            snippet_button.setStyleSheet(s["qss_QPushButton"])

        dropdown_button.setStyleSheet(s["qss_QToolButton"])

        dropdown_terminal_button.setStyleSheet(s["qss_QToolButton"])
        dropdown_terminal_menu.setStyleSheet(s["qss_QMenu"])
        btn_add_console.setStyleSheet(s["qss_QPushButtonTerminal"])
        if btn_add_left:
            btn_add_left.setStyleSheet(s["qss_QPushButtonTerminal"])
        btn_collapse = c.widgets.get("btn_collapse_terminal")
        if btn_collapse:
            _bg = theme.get("background", {})
            _fg = theme.get("foreground", {})
            btn_collapse.setStyleSheet(f"""
                QPushButton {{
                    background-color: {_bg.get("buttons", "#37373B")};
                    color: {_fg.get("text", "#ffffff")};
                    font-size: 7px;
                    padding: 0px;
                    border: none;
                }}
                QPushButton:hover {{
                    background-color: {_bg.get("buttons_hover", "#6C6C73")};
                }}
                QPushButton:pressed {{
                    background-color: {_bg.get("buttons_pressed", "#2C5F8F")};
                }}
            """)
        if btn_plus_menu:
            btn_plus_menu.setStyleSheet(s["qss_QToolButton"])
            if btn_plus_menu.menu():
                btn_plus_menu.menu().setStyleSheet(s["qss_QMenu"])

        dropdown_menu.setStyleSheet(s["qss_QMenu"])
        _bg_main = bg.get("main_window", "#2B2D30")
        settings_menu.setStyleSheet(
            s["qss_QDialog_global"] + s["qss_QLineEdit"] + s["qss_QComboBox"] +
            s["qss_QGroupBox"] +
            f"""
            QScrollArea#settings_scroll {{
                background-color: {_bg_main};
                border: none;
            }}
            QScrollArea#settings_scroll > QWidget {{
                background-color: {_bg_main};
            }}
            QWidget#settings_scroll_content {{
                background-color: {_bg_main};
            }}
            """
        )
        qterminal_dialog.setStyleSheet(s["qss_QDialog_global"])
        qt_dialog.setStyleSheet(s["qss_QDialog_global"])
        licenses_dialog.setStyleSheet(s["qss_QDialog_global"])
        if chat_webui_dialog:
            chat_webui_dialog.setStyleSheet(s["qss_QDialog_global"] + s["qss_QLineEdit"] + s["qss_QLabel"])
        chat_llama_dialog = c.widgets.get("chat_llama_dialog")
        if chat_llama_dialog:
            chat_llama_dialog.setStyleSheet(s["qss_QDialog_global"] + s["qss_QLineEdit"] + s["qss_QLabel"])
        chat_info_dialog = c.widgets.get("chat_info_dialog")
        if chat_info_dialog:
            chat_info_dialog.setStyleSheet(s["qss_QDialog_global"] + s["qss_QLabel"])

        slider_options_dialog.setStyleSheet(
            s["qss_QDialog"] + s["qss_QLineEdit_observable"] + s["qss_QPushButton"] +
            s["qss_QLabel"] + s["qss_QComboBox"] + s["qss_QTable"]
        )

        ObserverPanel.observable_panel_stylesheet = (
            s["qss_QLineEdit_slider"] + s["qss_QPushButton_slider"] +
            s["qss_QComboBox_slider"] + s["qss_QScrollArea"]
        )

        c.__class__.tabs_stylesheet = (
            s["qss_QWidget_tabs"] + s["qss_QPushButton"] + s["qss_QLineEdit"] + s["qss_QComboBox"] +
            s["qss_QLabel"] + s["qss_QScrollArea_tabs"] + s["qss_QCheckBox_tabs"] + s["qss_QTextEdit"] +
            s["qss_CustomUnsupportedLabel"] + s["qss_TextEditWithLineNumbers"] + s["qss_QToolTip"] +
            s["qss_FrameInfo"] + s["qss_QFrame_line"] + s["qss_QPlainTextEdit"] +
            s["qss_QPlainTextEdit_terminal"] + s["qss_QPlainTextEdit_docs"] + s["qss_QTable"]
        )
        c.__class__.messagebox_stylesheet = s["qss_QMesssageBox"]
        c.__class__.button_stylesheet = s["qss_QPushButton"]
        c.__class__.dialog_stylesheet = s["qss_QDialog_global"] + s["qss_QLineEdit"] + s["qss_QComboBox"]
        c.__class__.chat_panel_dialog_stylesheet = (
            s["qss_QDialog_global"] + s["qss_QLineEdit"] + s["qss_QComboBox"] +
            s["qss_QPushButton"] + s["qss_QLabel"] + s["qss_QScrollArea"] +
            f"""
            QLabel#manage_cat {{
                font-weight: bold;
                font-size: 10px;
                color: {fg.get("text", "#ffffff")};
                padding: 6px 4px 2px 4px;
            }}
            QLabel#manage_name {{
                color: {fg.get("text", "#ffffff")};
                font-size: 11px;
            }}
            QLabel#manage_cmd {{
                color: {fg.get("text_disabled", "#AAAAAA")};
                font-size: 11px;
            }}
            QWidget#manage_row {{
                background-color: {bg.get("side_frame", "#343436")};
                border-radius: 3px;
            }}
            """
        )
        c.__class__.menu_stylesheet = s["qss_QMenu"]
        c.__class__.command_palette_stylesheet = (
            s["qss_QDialog_global"] + s["qss_QLineEdit"] + s["qss_QScrollArea"] +
            f"""
            QListWidget {{
                background-color: {bg.get("main_window", "#2B2D30")};
                color: {fg.get("text", "#ffffff")};
                border: 1px solid {bd.get("default", "#555")};
                border-radius: 4px;
                outline: none;
            }}
            QListWidget::item {{
                padding: 4px 8px;
                border-bottom: 1px solid {bg.get("tab_bar", "#3c3f41")};
            }}
            QListWidget::item:hover {{
                background-color: {bg.get("buttons_hover", "#6C6C73")};
            }}
            QListWidget::item:selected {{
                background-color: {bg.get("buttons_pressed", "#2C5F8F")};
                color: {fg.get("text", "#ffffff")};
            }}
            """
        )
        c.__class__.qss_QPainter = s["qss_QPainter"]
        c.__class__.terminals_stylesheet = terminal_color["colorscheme"]
        c.__class__.terminal_qss_scroll = s["terminal_qss_scroll"]
        c.__class__.qss_QInputDialog_terminal = s["qss_QInputDialog"]

        for name, obj in c.widgets.items():
            if name.startswith("tab_container"):
                obj.setStyleSheet(c.__class__.tabs_stylesheet)
            if name == "observer_row_scroll":
                obj.setStyleSheet(ObserverPanel.observable_panel_stylesheet)

        for name, obj in c.panel_widgets.items():
            if name.startswith("observer_row"):
                obj.setStyleSheet(ObserverPanel.observable_panel_stylesheet)

        c.__class__.text_loaders[:] = [obj for obj in c.__class__.text_loaders if not isdeleted(obj)]
        for text_edit in c.__class__.text_loaders:
            if hasattr(text_edit, "update_painter_colors"):
                text_edit.update_painter_colors()

        c.__class__.text_highlighters[:] = [obj for obj in c.__class__.text_highlighters if not isdeleted(obj)]
        for highlighter in c.__class__.text_highlighters:
            if hasattr(highlighter, "update_colors"):
                highlighter.update_colors()

        # app.setStyleSheet wewnątrz bloku — main_window nie repaintuje
        # podczas rekalkukacji stylu globalnego
        app.setStyleSheet(s["qss_QToolTip"])

    finally:
        main_window.setUpdatesEnabled(True)

    # Rozwiązanie 2: setColorScheme odroczone na po wyrenderowaniu UI.
    # QTermWidget.setColorScheme() wymusza pełny repaint scrollback buffera
    # każdego terminala — najdroższa operacja w całym change_theme.
    # Odroczenie sprawia że UI zmienia się natychmiast, terminale doganiają po chwili.
    _terminal_stylesheet = s["terminal_qss_scroll"]
    _colorscheme = terminal_color["colorscheme"]

    _wrapper_bg = bg.get('scroll_area', '#1E1F22')

    def _apply_terminal_schemes():
        for terminal in list(c.__class__.terminals.values()):
            try:
                terminal.setStyleSheet(_terminal_stylesheet)
                terminal.setColorScheme(_colorscheme)
                terminal.update()
            except Exception:
                pass
        for wrapper in list(c.wrapper_to_console.keys()):
            try:
                wrapper.setAutoFillBackground(True)
                wrapper.setStyleSheet(f"background: {_wrapper_bg};")
            except Exception:
                pass
        _chat_term_widget = c.widgets.get("chat_term_active")
        if _chat_term_widget:
            try:
                _chat_term_widget.setStyleSheet(_terminal_stylesheet)
                _chat_term_widget.setColorScheme(_colorscheme)
                _chat_term_widget.update()
            except Exception:
                pass

    QTimer.singleShot(50, _apply_terminal_schemes)

    _text = fg.get('text', '#ffffff')
    _bg_main = bg.get('main_window', '#2B2D30')
    _bg_btn = bg.get('buttons', '#37373B')
    _bg_hover = bg.get('buttons_hover', '#6C6C73')
    _bg_input = bg.get('tab_bar', '#3B3E40')
    _border = bg.get('buttons_pressed', '#2C5F8F')

    def _restyle_search_bars():
        for term_widget in c.terminals.values():
            if not getattr(term_widget, '_style_children_cache', None):
                term_widget._style_children_cache = term_widget.findChildren(QWidget)
            for child in term_widget._style_children_cache:
                if isinstance(child, QLineEdit):
                    child.setStyleSheet(
                        f"QLineEdit {{ background: {_bg_input}; color: {_text};"
                        f" border: 1px solid {_border}; border-radius: 3px; padding: 2px 4px; }}"
                    )
                elif isinstance(child, (QToolButton, QPushButton)):
                    child.setStyleSheet(
                        f"QToolButton, QPushButton {{ background: {_bg_btn}; color: {_text};"
                        f" border: none; border-radius: 3px; padding: 2px 6px; }}"
                        f"QToolButton:hover, QPushButton:hover {{ background: {_bg_hover}; }}"
                        f"QToolButton:pressed, QPushButton:pressed {{ background: {_border}; }}"
                    )
                elif not hasattr(child, 'sendText'):
                    child.setStyleSheet(f"background: {_bg_main}; color: {_text};")

    QTimer.singleShot(30, _restyle_search_bars)

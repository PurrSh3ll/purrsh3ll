def build_terminal_styles(bg, fg, bd) -> dict:
    terminal_qss_scroll = f"""
            QScrollBar:vertical {{
                background: "transparent";
            }}

            QScrollBar::handle:vertical {{
                background: {bg.get("scroll", "#555555")};
                border-radius: 6px;
                border: 1px solid {bg.get("scroll", "#3a3a3a")};
            }}
            QScrollBar::handle:vertical:hover {{
                background: {bg.get("scroll_handle", "#707070")};
            }}
            QScrollBar::handle:vertical:pressed {{
                background: {bg.get("scroll_pressed", "#888888")};
            }}

            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                background: none;
                border: none;
            }}

            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: {bg.get("scroll_area", "#1E1F22")};
            }}

        """

    qss_QTabWidget_terminal = f"""
        QTabWidget > QWidget {{
        background: {bg.get("tab_bar_selected", "#1E1F22")};
        }}
        QTabBar::tab {{
            background: {bg.get("tab_bar", "#3B3E40")};
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            min-height: 24px;
        }}
        QTabBar::tab:selected {{
            background: {bg.get("tab_bar_selected", "#1E1F22")};
        }}
        QTabBar::tab:hover {{
            background: {bg.get("tab_bar_hover", "#777777")};
            color: {fg.get("tab_bar_hover", "#ffffff")};
        }}
    """

    qss_QPushButtonTerminal = f"""
    QPushButton {{
            background-color: {bg.get("buttons", "#37373B")};
            color: {fg.get("text", "#ffffff")};
        }}
        QPushButton:disabled {{
            background-color: {bg.get("buttons_disabled", "#555555")};
            color: {fg.get("text_disabled", "#AAAAAA")};
        }}

        QPushButton:hover {{
            background-color: {bg.get("buttons_hover", "#6C6C73")};
            color: {fg.get("text_hover", "#ffffff")};
        }}
        QPushButton:pressed {{
            background-color: {bg.get("buttons_pressed", "#2C5F8F")};
            color: {fg.get("text_pressed", "#ffffff")};
        }}

    """

    return {
        "terminal_qss_scroll": terminal_qss_scroll,
        "qss_QTabWidget_terminal": qss_QTabWidget_terminal,
        "qss_QPushButtonTerminal": qss_QPushButtonTerminal,
    }

def build_container_styles(bg, fg, bd, gl) -> dict:
    qss_QMainWindow = f"""
                    QMainWindow {{
                        background: qlineargradient(
                            x1: 0, y1: 0,
                            x2: 0, y2: 1,
                            stop: 0 {bg.get('main_window_start', '#2B2D30')},
                            stop: 1 {bg.get('main_window_stop', '#2B2D30')}
                        );
                    }}
                """

    qss_QSplitter = f"""
            QSplitter::handle {{
                background-color: 'transparent';
            }}
        """

    qss_QGroupBox = f"""
            QGroupBox {{
                background-color: 'transparent';
                color: {fg.get('group_box', '#ffffff')};
            }}
        """

    qss_QFrame_line = f"""
    QFrame#line{{
        border-top: 2px solid {bd.get("painter_lines", "#424242")}
        }}
        """

    qss_QFrame = f"""
        QFrame {{
            background: {bg.get("side_frame", "#343436")};
        }}
    """

    qss_QScrollArea = f"""
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

        QScrollBar:horizontal {{
            background: "transparent";
        }}

        QScrollBar::handle:horizontal {{
            background: {bg.get("scroll", "#555555")};
            border-radius: 6px;
            border: 1px solid {bd.get("scroll", "#3a3a3a")};
        }}
        QScrollBar::handle:horizontal:hover {{
            background: {bg.get("scroll_handle", "#707070")};
        }}
        QScrollBar::handle:horizontal:pressed {{
            background: {bg.get("scroll_pressed", "#888888")};
        }}

        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            background: none;
            border: none;
        }}

        QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
            background: {bg.get("scroll_area", "#1E1F22")};
        }}
    """

    qss_QWidget = f"""
        QWidget {{
            background: {bg.get("side_frame", "#343436")};
        }}
    """

    return {
        "qss_QMainWindow": qss_QMainWindow,
        "qss_QSplitter": qss_QSplitter,
        "qss_QGroupBox": qss_QGroupBox,
        "qss_QFrame_line": qss_QFrame_line,
        "qss_QFrame": qss_QFrame,
        "qss_QScrollArea": qss_QScrollArea,
        "qss_QWidget": qss_QWidget,
    }

def build_button_styles(bg, fg, bd, gl) -> dict:
    qss_QPushButton = f"""
        QPushButton {{
            background-color: {bg.get("buttons", "#37373B")};
            color: {fg.get("text", "#ffffff")};
        }}
        QPushButton[confirmed="true"] {{
            background-color: {bg.get("buttons_pressed", "#2C5F8F")};
            color: {fg.get("text_activated", "#ffffff")};
        }}
        QLabel[confirmed="true"] {{
            background-color: {bg.get("buttons_pressed", "#2C5F8F")};
            color: {fg.get("text_activated", "#ffffff")};
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

        QPushButton:checked {{
            background-color: {bg.get("buttons_pressed", "#2C5F8F")};
            color: {fg.get("text_pressed", "#ffffff")};
        }}
        QToolButton {{
            background-color: {bg.get("buttons", "#37373B")};
            color: {fg.get("text", "#ffffff")};
        }}
        QToolButton[confirmed="true"] {{
            background-color: {bg.get("buttons_pressed", "#2C5F8F")};
            color: {fg.get("text_activated", "#ffffff")};
        }}
        QToolButton:disabled {{
            background-color: {bg.get("buttons_disabled", "#555555")};
            color: {fg.get("text_disabled", "#AAAAAA")};
        }}
        QToolButton:hover {{
            background-color: {bg.get("buttons_hover", "#6C6C73")};
            color: {fg.get("text_hover", "#ffffff")};
        }}
        QToolButton:pressed {{
            background-color: {bg.get("buttons_pressed", "#2C5F8F")};
            color: {fg.get("text_pressed", "#ffffff")};
        }}
    """

    qss_QToolButton = f"""
        QToolButton {{
            margin-top: 1px;
            border-radius: "border_radius", "2px";
            color: {fg.get("text", "#ffffff")};
            background-color: {bg.get("buttons", "#37373B")};

        }}
        QToolButton::menu-indicator {{
            image: none;
        }}
        QToolButton:pressed,
        QToolButton:checked {{
            background-color: {bg.get("main_window", "#2B2D30")};
            color: {fg.get("tool_button_disabl", "#666666")};

        }}
        QToolButton:disabled {{
            background-color: {bg.get("main_window", "#2B2D30")};
            color: {fg.get("tool_button_disabl", "#666666")};

        }}
    """

    qss_QCheckBox_tabs = f"""
        QCheckBox {{
            background: "transparent";
            color: {fg.get("text", "#ffffff")};
        }}
        QCheckBox:hover {{
            background: {bg.get("check_box_hover", "#6C6C73")};
        }}

        QCheckBox:checked {{
            color: {bg.get("buttons_pressed", "#2C5F8F")};
        }}

        QCheckBox::indicator {{

            background: "transparent";
            border: 1px solid {bd.get("checkbox_indicator", "#555")};
        }}

        QCheckBox::indicator:hover {{
            border: 1px solid {bd.get("checkbox_indicator", "#555")};
        }}

        QCheckBox::indicator:checked {{
            background: {bg.get("check_box_ind_chk", "#2C5F8F")};
        }}

        """

    return {
        "qss_QPushButton": qss_QPushButton,
        "qss_QToolButton": qss_QToolButton,
        "qss_QCheckBox_tabs": qss_QCheckBox_tabs,
    }

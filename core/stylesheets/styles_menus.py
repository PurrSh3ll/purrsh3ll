def build_menu_styles(bg, fg, bd, gl) -> dict:
    qss_QMenu = f"""
           QMenuBar {{
               background-color: 'transparent';
           }}
           QMenuBar::item {{
               background-color: 'transparent';
               color: {fg.get("menu_bar", "#ffffff")};
           }}
           QMenuBar::item:selected {{
               background-color: {bg.get("menu_bar_hover", "#6C6C73")};
               color: {fg.get("menu_bar_hover", "#ffffff")};
           }}

           QMenu {{
               background-color: {bg.get("main_window", "#2B2D30")};
               border: {bd.get("default", "#555")};
           }}
           QMenu::item {{
               background-color: 'transparent';
               color: {fg.get("menu", "#ffffff")};
           }}
           QMenu::item:selected {{
               background-color: {bg.get("menu_hover", "#2C5F8F")};
               color: {fg.get("menu_hover", "#ffffff")};
           }}
           """

    qss_QDialog = f"""
            QDialog {{
                background-color: {bg.get("side_frame", "#343436")};
            }}
        """

    qss_QDialog_global = f"""
            QDialog {{
                background-color: {bg.get("main_window", "#2B2D30")};
            }}
            QLabel {{
                color: {fg.get("text", "#ffffff")};
            }}
            QPushButton {{
                background-color: {bg.get("buttons", "#37373B")};
                color: {fg.get("text", "#ffffff")};

            }}

            QPushButton:hover {{
                background-color: {bg.get("buttons_hover", "#6C6C73")};
                color: {fg.get("text_hover", "#ffffff")};
            }}

            QPushButton:pressed {{
                background-color: {bg.get("buttons_pressed", "#2C5F8F")};
                color: {fg.get("text_pressed", "#ffffff")};
            }}

            QPushButton:focus {{
                border: 1px solid {fg.get("text", "#ffffff")};
                border-radius: 6px;
                outline: none;
            }}
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
            QSpinBox {{
                background-color: {bg.get("tab_bar_selected", "#1E1F22")};
                color: {fg.get("text", "#ffffff")};
                border: 1px solid {bd.get("default", "#555")};
                border-radius: 4px;
                padding: 2px 6px;
            }}
            QSpinBox:hover {{
                border: 1px solid {bd.get("default", "#555")};
            }}
            QSpinBox::up-button, QSpinBox::down-button {{
                background-color: {bg.get("buttons", "#37373B")};
                border-left: 1px solid {bd.get("default", "#555")};
                width: 16px;
            }}

            """

    qss_QMesssageBox = f"""
            QMessageBox {{
                    background-color: {bg.get("main_window", "#2B2D30")};
                }}

                QLabel {{
                    color: {fg.get("text", "#ffffff")};
                    font-size: 14px;

                }}

                QPushButton {{
                    background-color: {bg.get("buttons", "#37373B")};
                    color: {fg.get("text", "#ffffff")};

                }}

                QPushButton:hover {{
                    background-color: {bg.get("buttons_hover", "#6C6C73")};
                    color: {fg.get("text_hover", "#ffffff")};
                }}

                QPushButton:pressed {{
                    background-color: {bg.get("buttons_pressed", "#2C5F8F")};
                    color: {fg.get("text_pressed", "#ffffff")};
                }}

                QPushButton:focus {{
                    border: 1px solid {fg.get("text", "#ffffff")};
                    border-radius: 6px;
                    outline: none;
                }}

                """

    qss_QToolTip = f"""
        QToolTip {{
            background-color: {bg.get("tooltip", "#2B2D30")};
            color: {fg.get("tooltip", "#ffffff")};
            border: 1px solid {bg.get("tooltip", "#4E4E4E")};
            }}

            """

    qss_QInputDialog = f"""
    QInputDialog {{
        background-color: {bg.get("main_window", "#2B2D30")};
        color: {fg.get("text", "#ffffff")};
    }}
    QLabel {{
        color: {fg.get("text", "#ffffff")};
        font-size: 13px;
    }}
    QLineEdit {{
        background-color: {bg.get("line_edit", "#3B3E40")};
        color: {fg.get("text", "#ffffff")};
        border: 1px solid {bd.get("default", "#555")};
        padding: 4px;
        border-radius: 4px;
        selection-background-color: {bg.get("text_edit_selected", "#308CC6")};
        selection-color: {fg.get("text_edit_selected", "#ffffff")};
    }}
    QPushButton, QDialogButtonBox QPushButton {{
        background-color: {bg.get("buttons", "#37373B")};
        color: {fg.get("text", "#ffffff")};
        border: 1px solid {bd.get("default", "#555")};
        border-radius: 4px;
        padding: 4px 10px;
    }}
    QPushButton:hover, QDialogButtonBox QPushButton:hover {{
        background-color: {bg.get("buttons_hover", "#6C6C73")};
        color: {fg.get("text_hover", "#ffffff")};
    }}
    QPushButton:pressed, QDialogButtonBox QPushButton:pressed {{
        background-color: {bg.get("buttons_pressed", "#2C5F8F")};
        color: {fg.get("text_pressed", "#ffffff")};
    }}
    """

    return {
        "qss_QMenu": qss_QMenu,
        "qss_QDialog": qss_QDialog,
        "qss_QDialog_global": qss_QDialog_global,
        "qss_QMesssageBox": qss_QMesssageBox,
        "qss_QToolTip": qss_QToolTip,
        "qss_QInputDialog": qss_QInputDialog,
    }

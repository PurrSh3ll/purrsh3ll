def build_panel_styles(bg, fg, bd) -> dict:
    qss_QLineEdit_observable = f"""
        QLineEdit {{
             background-color: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 {bg.get("gradient_start", "#2E323C")},
                stop:1 {bg.get("gradient_stop", "#1E2127")}
            );
            color: {fg.get("text", "#ffffff")};
            border: {bd.get("gradient", "#3A3D44")};
            selection-background-color: {bg.get('text_edit_selected', '#555')};
            selection-color: {fg.get('text_edit_selected', '#555')};
            border-radius: 6px;
            padding: 4px 8px;
        }}
        QLineEdit[confirmed="true"] {{
             background-color: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 {bg.get("buttons_pressed", "#2C5F8F")},
                stop:1 {bg.get("buttons_pressed", "#2C5F8F")}
            );
            color: {fg.get("text_activated", "#ffffff")};
            border: {bd.get("gradient_hover", "#4C8DFF")};
            selection-background-color: {bg.get('text_edit_selected', '#555')};
            selection-color: {fg.get('text_edit_selected', '#555')};
            border-radius: 6px;
            padding: 4px 8px;
        }}

        QLineEdit:hover[confirmed="true"] {{
             background-color: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 {bg.get("buttons_pressed", "#2C5F8F")},
                stop:1 {bg.get("buttons_pressed", "#2C5F8F")}
            );
            border: {bd.get("gradient_hover", "#4C8DFF")};
        }}

        QLineEdit:hover {{
            background-color: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 {bg.get("gradient_hover_start", "#353A46")},
                stop:1 {bg.get("gradient_hover_stop", "#23262D")}
            );
            border: {bd.get("gradient_hover", "#4C8DFF")};
        }}
        QLineEdit:focus[confirmed="true"] {{
             background-color: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 {bg.get("buttons_pressed", "#2C5F8F")},
                stop:1 {bg.get("buttons_pressed", "#2C5F8F")}
            );
            border: {bd.get("gradient_hover", "#4C8DFF")};
        }}

        QLineEdit:focus {{
            background-color: {bg.get("gradient_pressed", "#1E2026")};
            border: {bd.get("gradient_hover", "#4C8DFF")};
        }}
    """

    qss_QLabel_observable = f"""
        QLabel {{
            background-color: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 {bg.get("gradient_start", "#2E323C")},
                stop:1 {bg.get("gradient_stop", "#1E2127")}
            );
            color: {fg.get("text", "#ffffff")};
            border: {bd.get("gradient", "#3A3D44")};
            border-radius: 6px;
            padding: 6px 10px;
        }}

        QLabel:hover {{
            border: {bd.get("gradient_hover", "#4C8DFF")};
        }}
    """

    qss_QPushButton_slider = f"""
            QPushButton {{
                background-color: {bg.get("buttons_ob_panel", "#37373B")};
                color: {fg.get("text_ob_panel", "#ffffff")};
            }}
            QPushButton[confirmed="true"] {{
                background-color: {bg.get("buttons_pressed_ob_panel", "#2C5F8F")};
                color: {fg.get("text_activated_ob_panel", "#ffffff")};
            }}
            QLabel[confirmed="true"] {{
                background-color: {bg.get("buttons_pressed_ob_panel", "#2C5F8F")};
                color: {fg.get("text_activated_ob_panel", "#ffffff")};
            }}
            QPushButton:disabled {{
                background-color: {bg.get("buttons_disabled_ob_panel", "#555555")};
                color: {fg.get("text_disabled_ob_panel", "#AAAAAA")};
            }}

            QPushButton:hover {{
                background-color: {bg.get("buttons_hover_ob_panel", "#6C6C73")};
                color: {fg.get("text_hover_ob_panel", "#ffffff")};
            }}
            QPushButton:pressed {{
                background-color: {bg.get("buttons_pressed_ob_panel", "#2C5F8F")};
                color: {fg.get("text_pressed_ob_panel", "#ffffff")};
            }}

            QPushButton:checked {{
                background-color: {bg.get("buttons_pressed_ob_panel", "#2C5F8F")};
                color: {fg.get("text_pressed_ob_panel", "#ffffff")};
            }}
        """

    qss_QComboBox_slider = f"""
            QComboBox {{
                background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 {bg.get("gradient_start_ob_panel", "#2E323C")},
                    stop:1 {bg.get("gradient_stop_ob_panel", "#1E2127")}
                );
                color: {fg.get("text_ob_panel", "#ffffff")};
                border: {bd.get("gradient_ob_panel", "#3A3D44")};
                border-radius: 6px;
                padding: 4px 8px;
            }}

            QComboBox[confirmed="true"] {{
                background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 {bg.get("buttons_pressed_ob_panel", "#2C5F8F")},
                    stop:1 {bg.get("buttons_pressed_ob_panel", "#2C5F8F")}
                );
                color: {fg.get("text_activated_ob_panel", "#ffffff")};
                border: {bd.get("gradient_ob_panel", "#3A3D44")};
                border-radius: 6px;
                padding: 4px 8px;
            }}

            QComboBox:hover {{
                background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 {bg.get("gradient_hover_start_ob_panel", "#353A46")},
                    stop:1 {bg.get("gradient_hover_stop_ob_panel", "#23262D")}
                );
                border: {bd.get("gradient_hover_ob_panel", "#4C8DFF")};
            }}

            QListView {{
                background-color: {bg.get("combo_box_abst_ob_panel", "#343436")};
                color: {fg.get("text_ob_panel", "#ffffff")};
                border-radius: 6px;
                padding: 4px;
            }}

            QListView::item {{
                background-color: {bg.get("combo_box_abst_ob_panel", "#343436")};
                color: {fg.get("text_ob_panel", "#ffffff")};
            }}

            QListView::item:hover {{
                background-color: {bg.get("buttons_pressed_ob_panel", "#2B2D30")};
                color: {fg.get("combo_item_hover_ob_panel", "#ffffff")};
                color: #000000;
            }}
            """

    qss_QLineEdit_slider = f"""
            QLineEdit {{
                 background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 {bg.get("gradient_start_ob_panel", "#2E323C")},
                    stop:1 {bg.get("gradient_stop_ob_panel", "#1E2127")}
                );
                color: {fg.get("text_ob_panel", "#ffffff")};
                border: {bd.get("gradient_ob_panel", "#3A3D44")};
                selection-background-color: {bg.get('text_edit_selected_ob_panel', '#555')};
                selection-color: {fg.get('text_edit_selected_ob_panel', '#555')};
                border-radius: 6px;
                padding: 4px 8px;
            }}
            QLineEdit[confirmed="true"] {{
                 background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 {bg.get("buttons_pressed_ob_panel", "#2C5F8F")},
                    stop:1 {bg.get("buttons_pressed_ob_panel", "#2C5F8F")}
                );
                color: {fg.get("text_activated_ob_panel", "#ffffff")};
                border: {bd.get("gradient_hover_ob_panel", "#4C8DFF")};
                selection-background-color: {bg.get('text_edit_selected_ob_panel', '#555')};
                selection-color: {fg.get('text_edit_selected_ob_panel', '#555')};
                border-radius: 6px;
                padding: 4px 8px;
            }}

            QLineEdit:hover[confirmed="true"] {{
                 background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 {bg.get("buttons_pressed_ob_panel", "#2C5F8F")},
                    stop:1 {bg.get("buttons_pressed_ob_panel", "#2C5F8F")}
                );
                border: {bd.get("gradient_hover_ob_panel", "#4C8DFF")};
            }}

            QLineEdit:hover {{
                background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 {bg.get("gradient_hover_start_ob_panel", "#353A46")},
                    stop:1 {bg.get("gradient_hover_stop_ob_panel", "#23262D")}
                );
                border: {bd.get("gradient_hover_ob_panel", "#4C8DFF")};
            }}
            QLineEdit:focus[confirmed="true"] {{
                 background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 {bg.get("buttons_pressed_ob_panel", "#2C5F8F")},
                    stop:1 {bg.get("buttons_pressed_ob_panel", "#2C5F8F")}
                );
                border: {bd.get("gradient_hover_ob_panel", "#4C8DFF")};
            }}

            QLineEdit:focus {{
                background-color: {bg.get("gradient_pressed_ob_panel", "#1E2026")};
                border: {bd.get("gradient_hover_ob_panel", "#4C8DFF")};
            }}
        """

    return {
        "qss_QLineEdit_observable": qss_QLineEdit_observable,
        "qss_QLabel_observable": qss_QLabel_observable,
        "qss_QPushButton_slider": qss_QPushButton_slider,
        "qss_QComboBox_slider": qss_QComboBox_slider,
        "qss_QLineEdit_slider": qss_QLineEdit_slider,
    }

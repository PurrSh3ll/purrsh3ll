def build_tree_tab_styles(bg, fg, bd, gl) -> dict:
    qss_QTreeWidget = f"""
        QTreeWidget {{
            background-color: {bg.get('tab_bar_selected', '#1E1F22')};
            color: {fg.get("text", "#ffffff")};
        }}
        QTreeWidget::item:selected {{
            background-color: {bg.get("tree_selected", "#2C5F8F")};
            color: {fg.get("tree_selected", "#ffffff")};
        }}
        QTreeWidget::item:selected:!active {{
            background-color: {bg.get("tree_unfocused", "#6C6C73")};
            color: {fg.get("tree_unfocused", "#ffffff")};
        }}
    """

    qss_QTabWidget = f"""
        QTabWidget > QWidget {{
        background: {bg.get("tab_bar_selected", "#1E1F22")};
        }}
        QTabBar::tab {{
            background: {bg.get("tab_bar", "#3B3E40")};
            color: {fg.get("tab_bar", "#ffffff")};
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            min-height: 24px;
        }}
        QTabBar::tab:selected {{
            background: {bg.get("tab_bar_selected", "#1E1F22")};
            color: {fg.get("tab_bar_selected", "#ffffff")};
        }}
        QTabBar::tab:hover {{
            background: {bg.get("tab_bar_hover", "#777777")};
            color: {fg.get("tab_bar_hover", "#ffffff")};
        }}
    """

    qss_QComboBox = f"""
    QComboBox {{
        background-color: qlineargradient(
            x1:0, y1:0, x2:1, y2:1,
            stop:0 {bg.get("gradient_start", "#2E323C")},
            stop:1 {bg.get("gradient_stop", "#1E2127")}
        );
        color: {fg.get("text", "#ffffff")};
        border: {bd.get("gradient", "#3A3D44")};
        border-radius: 6px;
        padding: 4px 8px;
    }}

    QComboBox[confirmed="true"] {{
        background-color: qlineargradient(
            x1:0, y1:0, x2:1, y2:1,
            stop:0 {bg.get("buttons_pressed", "#2C5F8F")},
            stop:1 {bg.get("buttons_pressed", "#2C5F8F")}
        );
        color: {fg.get("text_activated", "#ffffff")};
        border: {bd.get("gradient", "#3A3D44")};
        border-radius: 6px;
        padding: 4px 8px;
    }}

    QComboBox:hover {{
        background-color: qlineargradient(
            x1:0, y1:0, x2:1, y2:1,
            stop:0 {bg.get("gradient_hover_start", "#353A46")},
            stop:1 {bg.get("gradient_hover_stop", "#23262D")}
        );
        border: {bd.get("gradient_hover", "#4C8DFF")};
    }}

    QListView {{
        background-color: {bg.get("combo_box_abst", "#343436")};
        color: {fg.get("text", "#ffffff")};
        border-radius: 6px;
        padding: 4px;
    }}

    QListView::item {{
        background-color: {bg.get("combo_box_abst", "#343436")};
        color: {fg.get("text", "#ffffff")};
    }}

    QListView::item:hover {{
        background-color: {bg.get("buttons_pressed", "#2B2D30")};
        color: {fg.get("combo_item_hover", "#ffffff")};
        color: #000000;
    }}
    """

    qss_QWidget_tabs = f"""
    QWidget {{
        background-color: {bg.get("tab_bar_selected", "#1E1F22")};
    }}
    """

    qss_QScrollArea_tabs = f"""
        QScrollBar {{
            background: {bg.get("scroll", "#555555")};

        }}

        """

    qss_QTable = f"""
        QTableWidget {{
            background-color: {bg.get("side_frame", "#343436")};
            gridline-color: {gl.get("table", "#555555")};
            selection-background-color: {bg.get("buttons_pressed", "#2C5F8F")};
            selection-color: {fg.get("text", "#ffffff")};
            alternate-background-color: {bg.get("table_alt", "#3D3D40")};
            color: {fg.get("text", "#ffffff")};

        }}
        QTableWidget::item:selected {{
            background-color: {bg.get("buttons_pressed", "#2C5F8F")};
            color: {fg.get("table_selected", "#ffffff")};
        }}

        QHeaderView::section {{
            background-color: {bg.get("table_header", "#2B2D30")};
            color: {fg.get("text", "#ffffff")};
            border: 1px solid {gl.get("table", "#555555")};
            padding: 4px;
        }}
        """

    return {
        "qss_QTreeWidget": qss_QTreeWidget,
        "qss_QTabWidget": qss_QTabWidget,
        "qss_QComboBox": qss_QComboBox,
        "qss_QWidget_tabs": qss_QWidget_tabs,
        "qss_QScrollArea_tabs": qss_QScrollArea_tabs,
        "qss_QTable": qss_QTable,
    }

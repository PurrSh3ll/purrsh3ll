def build_input_styles(bg, fg, bd, gl) -> dict:
    qss_QLineEdit = f"""
            QLineEdit {{
                background-color: {bg.get('line_edit', '#3B3E40')};
                color: {fg.get("text", "#ffffff")};
                border: {bd.get('default', '#555')};
                selection-background-color: {bg.get('text_edit_selected', '#555')};
                selection-color: {fg.get('text_edit_selected', '#555')};
            }}
        """

    qss_TextEditWithLineNumbers = f"""
    QPlainTextEdit#text_edit_line_numb {{
            color: {fg.get("text", "#ffffff")};
            selection-background-color: {bg.get("text_edit_selected", "#308CC6")};
            selection-color: {fg.get("text_edit_selected", "#ffffff")};

            font - family: "Courier New", monospace;

    }}
    """

    qss_QPlainTextEdit = f"""
    QPlainTextEdit{{
            color: {fg.get("text", "#ffffff")};
            selection-background-color: {bg.get("text_edit_selected", "#308CC6")};
            selection-color: {fg.get("text_edit_selected", "#ffffff")};
            font - family: "Courier New", monospace;
    }}
    """

    qss_QPlainTextEdit_terminal = f"""
    QPlainTextEdit#script_term{{
            color: {fg.get("script_term", "#ffffff")};
            background: {bg.get("script_term", "#000000")};
            selection-background-color: {bg.get("text_edit_selected", "#308CC6")};
            selection-color: {fg.get("text_edit_selected", "#ffffff")};
            font - family: "Courier New", monospace;
    }}
    """

    qss_QPlainTextEdit_docs = f"""
    QPlainTextEdit#docs{{
            color: {fg.get("painter_text", "#AAAAAA")};
            background: {bg.get("side_frame", "#343436")};
            selection-background-color: {bg.get("text_edit_selected", "#308CC6")};
            selection-color: {fg.get("text_edit_selected", "#ffffff")};
            font - family: "Courier New", monospace;
            border: 2px solid {bd.get("default", "#555")};
            border-radius: 4px;

            padding: 3px;
            background-color: {bg.get("side_frame", "#343436")};

    }}
    """

    qss_QTextEdit = f"""
            QTextEdit {{
                color: {fg.get("text", "#ffffff")};
                selection-background-color: {bg.get("text_edit_selected", "#308CC6")};
                selection-color: {fg.get("text_edit_selected", "#ffffff")};
            }}
        """

    return {
        "qss_QLineEdit": qss_QLineEdit,
        "qss_TextEditWithLineNumbers": qss_TextEditWithLineNumbers,
        "qss_QPlainTextEdit": qss_QPlainTextEdit,
        "qss_QPlainTextEdit_terminal": qss_QPlainTextEdit_terminal,
        "qss_QPlainTextEdit_docs": qss_QPlainTextEdit_docs,
        "qss_QTextEdit": qss_QTextEdit,
    }

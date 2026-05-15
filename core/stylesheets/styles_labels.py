def build_label_styles(bg, fg, bd, gl) -> dict:
    qss_QLabel = f"""
        QLabel {{
            background: "transparent";
            color: {fg.get("text", "#ffffff")};
        }}
        QLabel:disabled {{
            color: {fg.get("text_disabled", "#AAAAAA")};
        }}
    """

    qss_CustomUnsupportedLabel = f"""
    QLabel#unsupported_info_label {{
        background-color: {bg.get("unsupported_label", "orange")};
        color: {fg.get("unsupported_label", "red")};
        border: 2px solid {bd.get("unsupported_label", "green")};
        border-radius: 6px;
        font-style: italic;
    }}
    """

    qss_FrameInfo = f"""
    QFrame#info {{
        background-color: {bg.get("frame_info","#eaf3ff")};
        border: 1px solid {bd.get("frame_info", "#c4d7f2")};
        border-radius: 6px;
        padding: 4px 8px;
    }}
    QLabel#info {{
        color: {fg.get("label_info", "#1b3a57")};
        font-size: 11px;
    }}
    QPushButton#info {{
        border: none;
        color: {bg.get("button_info","#1b3a57")};
        font-weight: bold;
        font-size: 12px;
        background: transparent;
    }}
    QPushButton#info:hover {{
     color: {bg.get("button_info_hover", "#ff5555")};
    }}
    """

    qss_QLabel_welcome = f"""
        QLabel {{
            background: "transparent";
            color: {fg.get("welcome_label", "#C9C9C9")};
        }}
    """

    return {
        "qss_QLabel": qss_QLabel,
        "qss_CustomUnsupportedLabel": qss_CustomUnsupportedLabel,
        "qss_FrameInfo": qss_FrameInfo,
        "qss_QLabel_welcome": qss_QLabel_welcome,
    }

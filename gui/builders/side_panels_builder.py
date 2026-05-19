from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QWidget, QScrollArea, QLabel,
    QPushButton, QSizePolicy, QPlainTextEdit,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QWheelEvent
import os

from core.controller import controller_instance
from gui.widgets.observable_panel import ObserverPanel
from gui.widgets.custom_frame import CustomFrame
from gui.dialogs.custom_dialog import CustomDialog
from gui.panels.snippet_panel import SnippetPanel

c = controller_instance

def build_side_panels(main_window):

    def create_notes_container():
        notes_panel = CustomFrame(c.widgets["central_widget"])
        notes_panel.resize(notes_panel.start_width, c.widgets["main_window"].height())
        notes_panel.move(c.widgets["main_window"].width() - notes_panel.start_width, 0)
        notes_panel.hide()

        notes_panel_layout = QVBoxLayout()
        notes_panel_layout.setContentsMargins(0, 0, 0, 0)
        notes_panel.setLayout(notes_panel_layout)

        notes_panel_scroll = QScrollArea()
        notes_panel_scroll.setWidgetResizable(True)

        notes_panel_content = QWidget()
        notes_panel_content_layout = QVBoxLayout(notes_panel_content)
        notes_panel_content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        notes_panel_scroll.setWidget(notes_panel_content)

        notes_path = os.path.join(c.base_path, "appdata", "psnotes.txt")

        notes_editor = QPlainTextEdit(notes_panel)
        notes_editor.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        notes_editor.setPlaceholderText("Write your notes here...")
        notes_editor.setViewportMargins(4, 4, 8, 4)

        try:
            if os.path.exists(notes_path):
                with open(notes_path, "r", encoding="utf-8") as f:
                    notes_editor.setPlainText(f.read())
        except Exception:
            pass

        def _save_notes():
            try:
                with open(notes_path, "w", encoding="utf-8") as f:
                    f.write(notes_editor.toPlainText())
            except Exception as e:
                pass

        notes_editor.textChanged.connect(_save_notes)

        def _notes_wheel_event(event: QWheelEvent):
            if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
                delta = event.angleDelta().y()
                if delta > 0:
                    notes_editor.zoomIn(1)
                elif delta < 0:
                    notes_editor.zoomOut(1)
                event.accept()
            else:
                QPlainTextEdit.wheelEvent(notes_editor, event)

        notes_editor.wheelEvent = _notes_wheel_event

        notes_panel_layout.addWidget(notes_editor)

        c.register_widget("notes_panel", notes_panel)
        c.register_widget("notes_panel_layout", notes_panel_layout)
        c.register_widget("notes_panel_scroll", notes_panel_scroll)
        c.register_widget("notes_panel_content_layout", notes_panel_content_layout)
        c.register_widget("notes_panel_content", notes_panel_content)
        c.register_widget("notes_editor", notes_editor)

    def create_slider_container():
        slide_panel = CustomFrame(c.widgets["central_widget"])
        slide_panel.resize(slide_panel.start_width, c.widgets["main_window"].height())
        slide_panel.hide()

        slide_panel_layout = QVBoxLayout(slide_panel)
        slide_panel_layout.setContentsMargins(0, 0, 0, 0)
        slide_panel_layout.setSpacing(6)

        op_rows_panel = ObserverPanel(c)
        op_rows_panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        slide_panel_layout.addWidget(op_rows_panel)

        button_row = QHBoxLayout()
        button_row.setSpacing(5)
        button_row.setAlignment(Qt.AlignmentFlag.AlignLeft)

        btn_height = 28

        panel_del_all_rows_btn = QPushButton("🗑️")
        panel_del_all_rows_btn.setToolTip("Remove All")
        panel_del_all_rows_btn.setMinimumHeight(btn_height)

        panel_options_btn = QPushButton("⚙️")
        panel_options_btn.setToolTip("Options")
        panel_options_btn.setMinimumHeight(btn_height)

        panel_slide_add_btn = QPushButton("➕")
        panel_slide_add_btn.setMinimumHeight(btn_height)

        for btn in (panel_del_all_rows_btn, panel_options_btn, panel_slide_add_btn):
            btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            button_row.addWidget(btn)

        slide_panel_layout.addLayout(button_row)

        c.register_widget("slide_panel", slide_panel)
        c.register_widget("panel_slide_add_btn", panel_slide_add_btn)
        c.register_widget("panel_options_btn", panel_options_btn)
        c.register_widget("panel_del_all_rows_btn", panel_del_all_rows_btn)
        c.register_widget("op_rows_panel", op_rows_panel)

    def create_mode_container():
        slide_panel = CustomFrame(c.widgets["central_widget"])
        slide_panel.resize(slide_panel.start_width, c.widgets["main_window"].height())
        slide_panel.move(c.widgets["main_window"].width() - slide_panel.start_width, 0)
        slide_panel.hide()

        slide_panel_layout = QVBoxLayout()
        slide_panel_layout.setContentsMargins(0, 0, 0, 0)
        slide_panel.setLayout(slide_panel_layout)

        slide_panel_scroll = QScrollArea()
        slide_panel_scroll.setWidgetResizable(True)

        panel_slide_content = QWidget()
        panel_slide_content_layout = QVBoxLayout(panel_slide_content)
        panel_slide_content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        slide_panel_scroll.setWidget(panel_slide_content)

        slide_panel_layout.addWidget(slide_panel_scroll)

        future_label = QLabel("⏳ This feature will be added in the future")
        future_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        future_label.setStyleSheet("color: white; font-size: 18px;")
        slide_panel_layout.addStretch(1)
        slide_panel_layout.addWidget(future_label, alignment=Qt.AlignmentFlag.AlignCenter)
        slide_panel_layout.addStretch(1)

        added_var_label = QLabel("")
        panel_slide_add_btn = QPushButton("")
        slide_panel_layout.addWidget(added_var_label, alignment=Qt.AlignmentFlag.AlignBottom)
        slide_panel_layout.addWidget(panel_slide_add_btn, alignment=Qt.AlignmentFlag.AlignBottom)

        c.register_widget("mode_panel", slide_panel)
        c.register_widget("mode_panel_layout", slide_panel_layout)
        c.register_widget("mode_panel_scroll", slide_panel_scroll)
        c.register_widget("panel_mode_content_layout", panel_slide_content_layout)
        c.register_widget("panel_mode_content", panel_slide_content)
        c.register_widget("panel_mode_add_btn", panel_slide_add_btn)
        c.register_widget("mode_added_var_label", added_var_label)
        c.register_widget("mode_future_label", future_label)

    def create_slider_dialog():
        slider_options_dialog = CustomDialog(parent=c.widgets["slide_panel"])
        c.register_widget("slider_options_dialog", slider_options_dialog)

    def create_snippet_container():
        panel = CustomFrame(c.widgets["central_widget"])
        panel.resize(panel.start_width, c.widgets["main_window"].height())
        panel.move(c.widgets["main_window"].width() - panel.start_width, 0)
        panel.hide()

        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)

        snippet_widget = SnippetPanel(c, parent=panel)
        snippet_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        panel_layout.addWidget(snippet_widget)

        c.register_widget("snippet_panel", panel)
        c.register_widget("snippet_widget", snippet_widget)

    create_notes_container()
    create_slider_container()
    create_mode_container()
    create_slider_dialog()
    create_snippet_container()

from PyQt6.QtWidgets import QFrame
from PyQt6.QtCore import Qt, QPoint
from PyQt6.QtGui import QMouseEvent
from core.controller import controller_instance

class CustomFrame(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setMouseTracking(True)
        self.c = controller_instance
        self.main_window = self.c.widgets["main_window"]

        self.resizing_left = False
        self.drag_position = QPoint()
        self.grip_width = 5
        self.start_width = 360

    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.MouseButton.LeftButton:
            x = event.position().x()
            if 0 <= x <= self.grip_width:
                self.resizing_left = True
                self.drag_position = event.globalPosition().toPoint()
                event.accept()
            else:
                self.resizing_left = False
                super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent):
        x = event.position().x()

        if 0 <= x <= self.grip_width:
            self.setCursor(Qt.CursorShape.SizeHorCursor)
        else:
            if not self.resizing_left:
                self.setCursor(Qt.CursorShape.ArrowCursor)

        if self.resizing_left:
            global_pos = event.globalPosition().toPoint()
            diff = global_pos - self.drag_position
            new_width = self.width() - diff.x()
            new_x = self.x() + diff.x()

            self.setGeometry(new_x, self.y(), new_width, self.height())
            self.drag_position = global_pos
            event.accept()
            self.c.set_position_slide_button()
            self.c.set_position_mode_button()
            self.c.set_position_notes_button()
            self.c.set_position_chat_button()
            self.c.set_position_snippet_button()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent):
        self.resizing_left = False
        self.setCursor(Qt.CursorShape.ArrowCursor)
        if self.width() < self.start_width:
            new_x = self.main_window.width() - self.start_width
            self.setGeometry(new_x, self.y(), self.start_width, self.height())
            self.c.set_position_slide_button()
            self.c.set_position_mode_button()
            self.c.set_position_notes_button()
            self.c.set_position_chat_button()
            self.c.set_position_snippet_button()

        if self.width() > self.main_window.width():
            new_width = self.main_window.width() - 4
            new_x = self.main_window.width() - new_width
            self.setGeometry(new_x, self.y(), new_width, self.height())
            self.c.set_position_slide_button()
            self.c.set_position_mode_button()
            self.c.set_position_notes_button()
            self.c.set_position_chat_button()
            self.c.set_position_snippet_button()

        super().mouseReleaseEvent(event)
from PyQt6.QtWidgets import (QMenuBar, QMenu, QSplitter, QApplication)
from PyQt6.QtCore import QObject, QEvent, QTimer, QRect, Qt
from core.controller import controller_instance
from PyQt6.QtWidgets import QApplication, QMainWindow, QFrame
from PyQt6.QtGui import QResizeEvent
from PyQt6.QtCore import QSize

class GlobalFilter(QObject):
    def __init__(self):
        super().__init__()
        self.c = controller_instance
        self.clicked_obj = []
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.process_click_events)
        self.collecting = False
        self.slide_panel =self.c.get_widget("slide_panel")
        self.mode_panel = self.c.get_widget("mode_panel")
        self.slide_button = self.c.get_widget("slide_button")
        self.mode_button = self.c.get_widget("mode_button")
        self.notes_button = self.c.get_widget("notes_button")
        self.notes_panel = self.c.get_widget("notes_panel")
        self.chat_button = self.c.get_widget("chat_button")
        self.chat_panel = self.c.get_widget("chat_panel")
        self.snippet_button = self.c.get_widget("snippet_button")
        self.snippet_panel = self.c.get_widget("snippet_panel")
        self.cursor_overridden = False

    def _should_override_cursor(self, panel, button, global_pos):
        if not panel.isVisible():
            return False
        local_pos = panel.mapFromGlobal(global_pos)
        edge_rect = QRect(0, 0, panel.grip_width, panel.height())
        local_to_button = button.mapFromGlobal(global_pos)
        over_button = button.rect().contains(local_to_button)
        return edge_rect.contains(local_pos) and not over_button

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.KeyPress:
            if (event.key() == Qt.Key.Key_P and
                    event.modifiers() == Qt.KeyboardModifier.ControlModifier):
                self.c.open_command_palette()
                return True

        if event.type() == QEvent.Type.MouseMove:
            global_pos = event.globalPosition().toPoint()

            should_override = (
                    self._should_override_cursor(self.slide_panel, self.slide_button, global_pos) or
                    self._should_override_cursor(self.mode_panel, self.mode_button, global_pos) or
                    self._should_override_cursor(self.notes_panel, self.notes_button, global_pos) or
                    self._should_override_cursor(self.chat_panel, self.chat_button, global_pos) or
                    self._should_override_cursor(self.snippet_panel, self.snippet_button, global_pos)
            )

            if should_override and not self.cursor_overridden:
                QApplication.setOverrideCursor(Qt.CursorShape.SizeHorCursor)
                self.cursor_overridden = True
            elif not should_override and self.cursor_overridden:
                QApplication.restoreOverrideCursor()
                self.cursor_overridden = False

        if isinstance(obj, QSplitter):
            try:
                self.c.center_welcome_text()
            except RuntimeError:
                pass

        if event.type() == QEvent.Type.MouseButtonPress:
            if not self.collecting:
                self.clicked_obj.clear()
                self.collecting = True
                self.timer.start(30)

            if obj not in self.clicked_obj:
                self.clicked_obj.append(obj)

        return super().eventFilter(obj, event)

    def process_click_events(self):
        self.collecting = False

        menu_bar = self.c.get_widget("menu_bar")
        menu_button = self.c.get_widget("menu_button")

        if any(
            o == menu_bar or
            o == menu_button or
            isinstance(o, QMenuBar) or
            isinstance(o, QMenu)
            for o in self.clicked_obj
        ):
            return

        self.c.widgets["menu_bar"].setVisible(False)
        self.c.widgets["menu_button"].setVisible(True)

        self.c.set_position_slide_panel()
        self.c.set_position_mode_panel()
        self.c.set_position_notes_panel()
        self.c.set_position_chat_panel()
        self.c.set_position_snippet_panel()


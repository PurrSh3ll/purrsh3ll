
from PyQt6.QtWidgets import QApplication, QLineEdit, QWidget, QVBoxLayout, QToolTip
from PyQt6.QtCore import Qt, QPoint

class ExpandingLineEdit(QLineEdit):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.textChanged.connect(self._on_text_changed)
        self._tooltip_visible = False
        self._text_overflow = False

    def _on_text_changed(self):
        metrics = self.fontMetrics()
        text_width = metrics.horizontalAdvance(self.text())
        self._text_overflow = text_width > self.width()

        if self._text_overflow:
            self._show_tooltip()
        else:
            self._hide_tooltip()

    def _show_tooltip(self):
        if not self.text():
            return
        global_pos = self.mapToGlobal(QPoint(25, self.height()-25))
        QToolTip.showText(global_pos, self.text(), self)
        self._tooltip_visible = True

    def _hide_tooltip(self):
        if self._tooltip_visible:
            QToolTip.hideText()
            self._tooltip_visible = False

    def enterEvent(self, event):
        super().enterEvent(event)
        if self._text_overflow:
            self._show_tooltip()

    def leaveEvent(self, event):
        super().leaveEvent(event)
        self._hide_tooltip()
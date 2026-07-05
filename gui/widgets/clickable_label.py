
from PyQt6.QtWidgets import QLabel
from PyQt6.QtCore import Qt, pyqtSignal


class ClickableLabel(QLabel):
    """A QLabel that emits `clicked` on a left-button press, so it can act as a
    button (used by the bottom-left status label to open the activity-log
    popup). The mouse cursor is left unchanged on hover."""

    clicked = pyqtSignal()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)

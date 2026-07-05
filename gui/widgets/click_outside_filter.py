
from PyQt6.QtCore import QObject, QEvent, QPoint, QRect


class ClickOutsideFilter(QObject):
    """Application-level event filter, installed only while a popup is open, that
    invokes `on_outside()` when a mouse press lands outside every tracked widget.

    Widgets passed in `inside_widgets` (e.g. the popup itself and the label that
    toggles it) are treated as "inside", so clicking them does not trigger the
    outside handler. The event is never consumed, so normal handling continues."""

    def __init__(self, inside_widgets, on_outside, parent=None):
        super().__init__(parent)
        self._inside = inside_widgets
        self._on_outside = on_outside

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.MouseButtonPress:
            gp = event.globalPosition().toPoint()
            for w in self._inside:
                if w is not None and w.isVisible():
                    rect = QRect(w.mapToGlobal(QPoint(0, 0)), w.size())
                    if rect.contains(gp):
                        return False  # inside a tracked widget — ignore
            self._on_outside()
        return False

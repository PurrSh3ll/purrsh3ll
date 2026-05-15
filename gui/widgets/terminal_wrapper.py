
from PyQt6 import QtWidgets, QtCore
from PyQt6.QtWidgets import QSizePolicy

class TerminalWrapper(QtWidgets.QWidget):
    def __init__(self, console_widget, min_h=40, pref_h=300, parent=None):
        super().__init__(parent)
        self._console = console_widget
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._console)

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self._pref_h = pref_h

        try:
            self._console.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        except Exception:
            pass

    def sizeHint(self):
        return QtCore.QSize(self.width(), self._pref_h)

    def minimumSizeHint(self):
        return QtCore.QSize(0, self.minimumHeight())
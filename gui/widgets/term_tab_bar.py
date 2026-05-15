from PyQt6.QtWidgets import QTabWidget, QTabBar
from PyQt6.QtCore import Qt, QPoint

class MyTabWidget(QTabWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setTabBar(MyTabBar(self))

class MyTabBar(QTabBar):
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.RightButton:
            index = self.tabAt(event.pos())

            if hasattr(self.parent(), "_on_tab_context"):
                self.parent()._on_tab_context(event.pos())

            return

        super().mousePressEvent(event)
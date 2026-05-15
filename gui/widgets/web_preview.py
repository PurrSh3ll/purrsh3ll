from PyQt6.QtWidgets import QMenu
from PyQt6.QtGui import QGuiApplication, QAction
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEnginePage

class WebPreview(QWebEngineView):
    def __init__(self, parent=None):
        super().__init__(parent)

    def contextMenuEvent(self, event):
        menu = QMenu(self)

        act_back = QAction("◀ Back", self)
        act_back.triggered.connect(self.back)
        act_back.setEnabled(self.history().canGoBack())
        menu.addAction(act_back)

        act_forward = QAction("Forward ▶", self)
        act_forward.triggered.connect(self.forward)
        act_forward.setEnabled(self.history().canGoForward())
        menu.addAction(act_forward)

        menu.addSeparator()

        act_select_all = QAction("Select all", self)
        act_select_all.triggered.connect(lambda: self.page().triggerAction(QWebEnginePage.WebAction.SelectAll))
        menu.addAction(act_select_all)

        act_copy = QAction("Copy", self)
        act_copy.triggered.connect(lambda: self.page().triggerAction(QWebEnginePage.WebAction.Copy))
        menu.addAction(act_copy)

        act_copy_url = QAction("Copy page URL", self)
        act_copy_url.triggered.connect(self._copy_page_url_to_clipboard)
        menu.addAction(act_copy_url)

        menu.addSeparator()

        act_reload = QAction("Reload", self)
        act_reload.triggered.connect(self.reload)
        menu.addAction(act_reload)

        menu.exec(event.globalPos())

    def _copy_page_url_to_clipboard(self):
        url = self.url().toString()
        if url:
            QGuiApplication.clipboard().setText(url)

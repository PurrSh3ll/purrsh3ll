import os
os.environ["QT_OPENGL"] = "software"
os.environ["QTWEBENGINE_DISABLE_GPU"] = "1"
os.environ["QTWEBENGINE_DISABLE_SANDBOX"] = "1"
import sys
from gui.main_window import MainWindow
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtGui import QIcon
from core.app_logger import setup_logging

_BASE_PATH = os.path.dirname(os.path.abspath(__file__))
setup_logging(_BASE_PATH, debug="--debug" in sys.argv)

def main():
    app = QApplication(sys.argv)
    app._warmup_view = QWebEngineView()
    app._warmup_view.hide()

    icon_path = os.path.join(os.path.dirname(__file__), "icons", "__app_icon.png")
    app.setWindowIcon(QIcon(icon_path))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()


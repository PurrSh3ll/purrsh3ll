# PurrSh3ll — AI-powered terminal and security toolkit
# Copyright (C) 2024-2025  PurrSh3ll Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

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


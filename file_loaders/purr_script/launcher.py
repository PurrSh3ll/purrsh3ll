import os, random, json, re, ast, sys, shutil, subprocess, threading, time
import csv
import hashlib
from pathlib import Path
import tempfile
import resource
import signal

from PyQt6.QtCore import QTimer
from collections import deque
import pydoc
import importlib.util

from PyQt6.QtGui import QDesktopServices
from PyQt6.QtCore import QUrl

from gui.panels.history_script_wdg import HistoryScriptWdg
from gui.panels.favorites_script_wdg import FavScriptWdg

from datetime import datetime
from pyfiglet import Figlet
from PyQt6.QtGui import QIntValidator, QFont
from PyQt6.QtCore import QObject, QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QPushButton,
    QSizePolicy,
    QPlainTextEdit,
    QTextEdit,
    QLabel,
    QCheckBox,
    QFrame,
    QLineEdit,
    QComboBox,
    QStackedLayout,
    QScrollArea
)

from file_loaders.purr_script.paths import PathsMixin
from file_loaders.purr_script.content import ContentMixin
from file_loaders.purr_script.execution import ExecutionMixin
from file_loaders.purr_script.ui import UIMixin
from file_loaders.purr_script.handlers import HandlersMixin

class VenvWorker(QObject):

    finished = pyqtSignal()

    def __init__(self, parent, controller):
        super().__init__()
        self.parent = parent
        self.controller = controller

    def run(self):
        self.controller.generate_venv_list_json()
        self.finished.emit()

class ScriptLauncher(PathsMixin, ContentMixin, ExecutionMixin, UIMixin, HandlersMixin, QWidget):
    install_requested = pyqtSignal()

    def __init__(self, parent=None, controller=None, path: str | None = None):
        super().__init__(parent=parent)
        self.path = path
        self.controller = controller
        self.controller_term_tabs = self.controller.widgets["terminal_tabs"]

        self.script_note_path = None
        self.script_history_path = None
        self.script_favorite_path = None

        self.script_help_path = None
        self.script_docs_path = None

        self.name = os.path.splitext(os.path.basename(self.path))[0]
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.missing_libs = None
        self.pip_term_open = False
        self.file_mtime = os.path.getmtime(self.path)

        self.favorite_text = "[-] Your Favorites list is empty. To add a command, go to the History tab and select command"
        self.help_text = "[-] No Help documentation found."
        self.docs_text = "[-] No Docstrings documentation found."
        self.history_text = "[-] Execution history is empty. The program has not been launched yet."
        self.notes_text = "[-] No notes created yet. You can create and attach notes to the script here."
        self.readme_text = "[-] No readme file found."

        self._term_buffer = ""
        self._max_buf = 50_000

        self._cmd_re = re.compile(r'echo\s+"?PurrSh3ll has ended >> instalation"?')
        self._out_re = re.compile(r'PurrSh3ll has ended >> instalation')

        self._last_processed_cmd_end = 0
        self._last_processed_out_end = 0

        self.get_notes_path()
        self.get_history_path()
        self.get_favorite_path()
        self.get_help_path()
        self.get_docs_path()

        self._notes_save_timer = QTimer(self)
        self._notes_save_timer.setSingleShot(True)
        self._notes_save_timer.timeout.connect(self._save_notes_to_file)

        self._last_saved_notes = None

        self.update_readme()
        self.update_docs()
        self.update_help()

        self.update_history()
        self.update_notes()

        self._build_ui()
        self.update_imports_info()

class Purr_script:
    def __init__(self):
        pass

    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        scroll = QScrollArea(parent=parent.widgets['execution_tabs'])
        scroll.setWidgetResizable(True)
        scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        widget = ScriptLauncher(
            parent=scroll,
            controller=parent,
            path=path
        )
        scroll.setWidget(widget)
        return scroll


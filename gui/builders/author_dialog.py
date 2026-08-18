# PurrSh3ll — author / about dialog builder
# Copyright (C) 2024-2025  PurrSh3ll Contributors
#
# Dialog builder extracted verbatim from menu_builder.build_menu so that huge
# function stops being a monolith. Behaviour-preserving: same body, same widget
# registrations via the controller; main_window is now an explicit parameter
# instead of a closure capture.

from PyQt6.QtWidgets import (
    QPushButton, QDialog, QFormLayout, QHBoxLayout, QVBoxLayout,
    QLabel, QSpinBox, QDoubleSpinBox, QCheckBox, QLineEdit, QComboBox, QGroupBox, QScrollArea, QWidget,
    QRadioButton, QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView, QTextEdit,
    QListView, QListWidget, QListWidgetItem, QMessageBox, QTabWidget, QSizePolicy,
    QToolButton, QSlider, QPlainTextEdit,
)
from PyQt6.QtCore import Qt, QTimer, QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QAction, QIntValidator
import os
import json
import subprocess
import threading
import logging

from core.controller import controller_instance

logger = logging.getLogger(__name__)
c = controller_instance


def create_author_dialog():
    author_dialog = QDialog()
    author_dialog.setWindowTitle("Author")
    author_dialog.setModal(True)
    layout = QVBoxLayout()
    author_label = QLabel("""
        <div style="text-align: center; padding: 16px;">
            <b style="font-size: 15px;">PurrSh3ll</b><br>
            <span style="color: gray;">AI-powered terminal environment for pentesters</span><br><br>

            <b>Damian Ząbek</b><br>
            Cybersecurity Specialist<br><br>

            <table cellspacing="8" style="margin: 0 auto;">
                <tr>
                    <td>🐱&nbsp;<b>GitHub</b></td>
                    <td><a href="https://github.com/PurrSh3ll/purrsh3ll">github.com/PurrSh3ll/purrsh3ll</a></td>
                </tr>
                <tr>
                    <td>💼&nbsp;<b>LinkedIn</b></td>
                    <td><a href="https://www.linkedin.com/in/damian-ząbek-905518364/">linkedin.com/in/damian-ząbek</a></td>
                </tr>
                <tr>
                    <td>📧&nbsp;<b>Email</b></td>
                    <td><a href="mailto:purrsh3ll@gmail.com">purrsh3ll@gmail.com</a></td>
                </tr>
                <tr>
                    <td>▶️&nbsp;<b>Demo</b></td>
                    <td><a href="https://youtu.be/kpUUVxBdFqE">youtu.be/kpUUVxBdFqE</a></td>
                </tr>
            </table><br>

            <span style="color: gray; font-size: 11px;">Released under the GNU General Public License v3.0</span>
        </div>
        """)
    author_label.setTextFormat(Qt.TextFormat.RichText)
    author_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
    author_label.setOpenExternalLinks(True)
    author_label.setWordWrap(True)
    layout.addWidget(author_label)
    author_dialog.setLayout(layout)
    author_dialog.resize(420, 300)
    try:
        c.register_widget("author_dialog", author_dialog)
    except Exception:
        pass

# PurrSh3ll — licenses & dependencies dialog builder
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


def create_licenses_dialog():
    licenses_dialog = QDialog()
    licenses_dialog.setWindowTitle("Licenses")
    licenses_dialog.setModal(True)
    layout = QVBoxLayout()
    licenses_label = QLabel("""
        <div style="text-align: left; padding: 8px;">
            <div style="text-align: center;"><b>Licenses and Dependencies</b></div><br>

            <b>Python Libraries</b><br>
            • <a href="https://pypi.org/project/PyQt6/">PyQt6 6.10.0</a> – GPL v3<br>
            • <a href="https://pypi.org/project/PyQt6-WebEngine/">PyQt6-WebEngine 6.10.0</a> – GPL v3<br>
            • <a href="https://pypi.org/project/pyqt6-sip/">pyqt6-sip 13.10.2</a> – GPL / MIT<br>
            • <a href="https://pypi.org/project/QtPy/">QtPy 2.4.3</a> – MIT<br>
            • <a href="https://github.com/lxqt/qtermwidget/">QTermWidget 2.2.0</a> – GPL v2<br>
            • <a href="https://pypi.org/project/watchdog/">watchdog 6.0.0</a> – Apache 2.0<br>
            • <a href="https://pypi.org/project/chromadb/">chromadb 1.5.9</a> – Apache 2.0<br>
            • <a href="https://pypi.org/project/fastembed/">fastembed 0.8.0</a> – Apache 2.0<br>
            • <a href="https://pypi.org/project/onnxruntime/">onnxruntime 1.26.0</a> – MIT<br>
            • <a href="https://pypi.org/project/huggingface-hub/">huggingface-hub 1.14.0</a> – Apache 2.0<br>
            • <a href="https://pypi.org/project/keyring/">keyring 25.7.0</a> – MIT<br>
            • <a href="https://pypi.org/project/SecretStorage/">SecretStorage 3.5.0</a> – BSD 3-Clause<br>
            • <a href="https://pypi.org/project/cryptography/">cryptography 46.0.5</a> – Apache 2.0 / BSD<br>
            • <a href="https://pypi.org/project/docker/">docker 7.1.0</a> – Apache 2.0<br>
            • <a href="https://pypi.org/project/pyfiglet/">pyfiglet 1.0.4</a> – MIT<br>
            • <a href="https://pypi.org/project/pygame/">pygame 2.6.1</a> – LGPL v2.1<br>
            • <a href="https://pypi.org/project/Pillow/">Pillow 12.0.0</a> – HPND<br>
            • <a href="https://pypi.org/project/pydantic/">pydantic 2.13.4</a> – MIT<br>
            • <a href="https://pypi.org/project/requests/">requests 2.32.5</a> – Apache 2.0<br>
            • <a href="https://pypi.org/project/PyYAML/">PyYAML 6.0.3</a> – MIT<br>
            • <a href="https://pypi.org/project/loguru/">loguru 0.7.3</a> – MIT<br>
            • <a href="https://pypi.org/project/rich/">rich 14.2.0</a> – MIT<br>
            • <a href="https://pypi.org/project/numpy/">numpy 2.4.4</a> – BSD 3-Clause<br>
            • <a href="https://pypi.org/project/pyte/">pyte 0.8.2</a> – LGPL v3<br>
            • <a href="https://pypi.org/project/markdown2/">markdown2 2.5.4</a> – MIT<br>
            • <a href="https://pypi.org/project/Pygments/">Pygments 2.19.2</a> – BSD 2-Clause<br>
            • <a href="https://pypi.org/project/jeepney/">jeepney 0.9.0</a> – MIT<br>
            • <a href="https://pypi.org/project/pymupdf/">PyMuPDF (fitz) 1.27.2.3</a> – AGPL v3<br>
            • <a href="https://pypi.org/project/mutagen/">mutagen 1.47.0</a> – GPL v2<br>
            • <a href="https://pypi.org/project/packaging/">packaging 25.0</a> – Apache 2.0 / BSD<br><br>

            <b>Voice &amp; Audio</b><br>
            • <a href="https://github.com/SYSTRAN/faster-whisper">faster-whisper 1.2.1</a> – MIT<br>
            • <a href="https://github.com/dscripka/openWakeWord">openwakeword 0.4.0</a> – Apache 2.0<br>
            • <a href="https://pypi.org/project/sounddevice/">sounddevice 0.5.5</a> – MIT<br>
            • <a href="https://pypi.org/project/scipy/">scipy 1.17.1</a> – BSD 3-Clause<br>
            • <a href="https://opennmt.net">ctranslate2 4.7.1</a> – MIT<br>
            • <a href="https://pypi.org/project/av/">av (PyAV) 17.0.1</a> – BSD 3-Clause<br>
            • <a href="https://scikit-learn.org">scikit-learn 1.8.0</a> – BSD 3-Clause<br>
            • <a href="https://github.com/huggingface/tokenizers">tokenizers 0.23.1</a> – Apache 2.0<br><br>

            <hr>
            <b>External Tools &amp; Resources</b><br>
            • <a href="https://exiftool.org">ExifTool</a> – Artistic / GPL<br><br>

            <hr>
            <b>Copyright &amp; Trademarks</b><br>
            • <b>Qt</b> — Copyright © The Qt Company Ltd. and other contributors.
              Used under GPL v3 via PyQt6. Qt and the Qt logo are trademarks of
              The Qt Company Ltd. — <a href="https://qt.io/licensing">qt.io/licensing</a><br>
            • <b>PyQt6</b> — Copyright © <a href="https://riverbankcomputing.com">Riverbank Computing Limited</a>.<br>
            • <b>QTermWidget</b> — Copyright © 2013–2026 LXQt Project —
              <a href="https://github.com/lxqt/qtermwidget">github.com/lxqt/qtermwidget</a><br><br>

            <hr>
            <div style="text-align: center; color: gray; font-size: 11px;">
                Full GPL / LGPL license texts are bundled in the <b>LICENSES/</b> folder of
                this project; per-dependency texts are available at the links above.
            </div>
        </div>
        """)
    licenses_label.setTextFormat(Qt.TextFormat.RichText)
    licenses_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
    licenses_label.setOpenExternalLinks(True)
    licenses_label.setWordWrap(True)

    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setWidget(licenses_label)

    layout.addWidget(scroll)
    licenses_dialog.setLayout(layout)
    licenses_dialog.resize(580, 520)
    try:
        c.register_widget("licenses_dialog", licenses_dialog)
        c.register_widget("licenses_label", licenses_label)
    except Exception as e:
        pass

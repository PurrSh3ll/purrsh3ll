
import os
import sys
from PyQt6.QtWidgets import (
    QScrollArea, QWidget, QVBoxLayout, QLabel, QHBoxLayout,
    QSizePolicy, QTextEdit, QPushButton, QFrame
)
from PyQt6.QtGui import QFont, QCursor
from PyQt6.QtCore import Qt, QProcess
from PyQt6.QtCore import QProcessEnvironment

from pyfiglet import Figlet

class Game_file:
    def __init__(self):
        self.target_widget = None
        self._process = None
        self._display = None
        self._container = None
        self._scroll = None
        self._controller = None

    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        self._controller = parent

        outer = QWidget(parent=parent.widgets['execution_tabs'])
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(6, 6, 6, 6)
        outer_layout.setSpacing(8)
        outer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        if self._controller.game_3d_info:
            info_bar = QFrame(outer)
            info_bar.setFrameShape(QFrame.Shape.StyledPanel)
            info_bar.setObjectName("info")

            info_layout = QHBoxLayout(info_bar)
            info_layout.setContentsMargins(6, 2, 6, 2)

            info_label = QLabel(
                "If you are using a a <b>virtual machine</b>, please note that for proper game performance "
                "it may be necessary to <b>disable 3D graphics acceleration</b> to allow the host CPU’s integrated GPU to be used."
            )
            info_label.setObjectName("info")
            info_label.setWordWrap(True)
            info_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            info_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)

            close_btn = QPushButton("✕")
            close_btn.setObjectName("info")
            close_btn.setFixedSize(16, 16)
            close_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))

            info_layout.addWidget(info_label, stretch=1)
            info_layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignTop)

            def hide_info_bar():
                info_bar.hide()
                self._controller.game_3d_info = False
            close_btn.clicked.connect(hide_info_bar)
            outer_layout.addWidget(info_bar)

        script_name = os.path.basename(path)
        script_base, _ = os.path.splitext(script_name)

        try:
            ascii_title = Figlet(font="ansi_shadow").renderText(script_base)

        except Exception:
            ascii_title = f"== {script_base} =="

        title_label = QLabel(ascii_title)
        title_label.setFont(QFont("Courier New", 10))
        title_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        title_label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        title_label.setWordWrap(False)
        title_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        title_container = QWidget()
        title_container_layout = QVBoxLayout(title_container)
        title_container_layout.setContentsMargins(0, 0, 0, 0)
        title_container_layout.addWidget(title_label)
        title_container.setLayout(title_container_layout)

        title_scroll = QScrollArea(outer)
        title_scroll.setWidgetResizable(True)
        title_scroll.setWidget(title_container)
        title_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        title_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        MAX_TITLE_HEIGHT = 180
        title_scroll.setMaximumHeight(MAX_TITLE_HEIGHT)

        logs_scroll = QScrollArea(outer)
        logs_scroll.setWidgetResizable(True)
        logs_container = QWidget()
        logs_layout = QVBoxLayout(logs_container)
        logs_layout.setContentsMargins(0, 0, 0, 0)
        logs_layout.setSpacing(0)

        info_edit = QTextEdit(logs_container)
        info_edit.setReadOnly(True)
        info_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        info_edit.setFont(QFont("Courier New", 10))
        logs_layout.addWidget(info_edit)
        logs_container.setLayout(logs_layout)
        logs_scroll.setWidget(logs_container)
        logs_scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        launch_button = QPushButton("Run game", outer)
        wrapper = QWidget(outer)
        w_layout = QHBoxLayout(wrapper)
        w_layout.setContentsMargins(0, 0, 0, 0)
        w_layout.addStretch(1)
        w_layout.addWidget(launch_button)
        w_layout.addStretch(1)
        wrapper.setMaximumWidth(200)

        outer_layout.addWidget(title_scroll)
        outer_layout.addWidget(logs_scroll)
        outer_layout.addWidget(wrapper, alignment=Qt.AlignmentFlag.AlignCenter)
        outer.setLayout(outer_layout)

        self.target_widget = outer if target_widget is None else target_widget
        outer._loader = self

        process = QProcess(outer)
        self._process = process

        def on_game_finished(exit_code: int, exit_status: QProcess.ExitStatus):
            info_edit.append("\nGame has been closed.")
            info_edit.append(f"Exit code: {exit_code}, Exit status: {exit_status.name}")
        process.finished.connect(on_game_finished)

        def launch_game():
            if process.state() != QProcess.ProcessState.NotRunning:
                info_edit.append("\nGame is already running")
                return

            if not os.path.exists(path):
                info_edit.append("\nFile not found: " + path)
                return

            env = QProcessEnvironment.systemEnvironment()

            env.insert("SDL_RENDER_DRIVER", "software")
            env.insert("SDL_RENDER_VSYNC", "0")
            env.insert("SDL_HINT_RENDER_BATCHING", "0")

            process.setProcessEnvironment(env)

            process.start(sys.executable, [path])
            if process.waitForStarted(1000):
                info_edit.append("\nGame launched...")
            else:
                info_edit.append("\nFailed to launch game.")
        launch_button.clicked.connect(launch_game)

        self._display = info_edit
        self._container = outer
        self._scroll = logs_scroll

        return outer

    def stop_game(self):
        if self._process is not None and self._process.state() != QProcess.ProcessState.NotRunning:
            try:
                self._process.terminate()
                if not self._process.waitForFinished(1000):
                    self._process.kill()
            except Exception:
                pass

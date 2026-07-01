
import json
import logging
import os
import sys
import webbrowser
from datetime import datetime

logger = logging.getLogger(__name__)

from PyQt6.QtWidgets import (
    QScrollArea, QWidget, QVBoxLayout, QLabel, QHBoxLayout,
    QSizePolicy, QTextEdit, QPushButton, QFrame
)
from PyQt6.QtGui import QFont, QCursor
from PyQt6.QtCore import Qt, QProcess, QProcessEnvironment

from pyfiglet import Figlet


def _is_html_game(path: str) -> bool:
    """Return True if the .game file starts with an HTML doctype or <html> tag."""
    try:
        with open(path, "rb") as f:
            head = f.read(512).lstrip().lower()
        return head.startswith(b"<!doctype html") or head.startswith(b"<html")
    except Exception:
        return False


def _load_last_run(config_path: str, game_path: str) -> int | None:
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("game_last_run", {}).get(game_path)
    except Exception:
        return None


def _save_last_run(config_path: str, game_path: str, ts: int):
    try:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
        data.setdefault("game_last_run", {})[game_path] = ts
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        logger.warning("failed to persist game_last_run to config", exc_info=True)


def _format_last_run(ts: int | None) -> str:
    if ts is None:
        return "Never run"
    diff = int(datetime.now().timestamp()) - ts
    if diff < 60:
        return "Last run: just now"
    if diff < 3600:
        return f"Last run: {diff // 60} min ago"
    if diff < 86400:
        return f"Last run: {diff // 3600}h ago"
    return f"Last run: {datetime.fromtimestamp(ts).strftime('%Y-%m-%d')}"


class Game_file:
    def __init__(self):
        self.target_widget = None
        self._process     = None
        self._display     = None
        self._container   = None
        self._scroll      = None
        self._controller  = None

    # ── public entry point ────────────────────────────────────────────────────
    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        self._controller = parent
        config_path      = self._controller.config_path
        html_game        = _is_html_game(path)
        script_base      = os.path.splitext(os.path.basename(path))[0]

        # ── outer container ───────────────────────────────────────────────────
        outer = QWidget(parent=parent.widgets['execution_tabs'])
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(12, 8, 12, 8)
        outer_layout.setSpacing(0)
        outer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # ── optional VM 3-D info bar ──────────────────────────────────────────
        if self._controller.game_3d_info and not html_game:
            info_bar    = QFrame(outer)
            info_bar.setFrameShape(QFrame.Shape.StyledPanel)
            info_bar.setObjectName("info")
            info_layout = QHBoxLayout(info_bar)
            info_layout.setContentsMargins(6, 2, 6, 2)

            info_label = QLabel(
                "If you are using a <b>virtual machine</b>, please note that for proper game "
                "performance it may be necessary to <b>disable 3D graphics acceleration</b> "
                "to allow the host CPU's integrated GPU to be used."
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

            def _hide_info():
                info_bar.hide()
                self._controller.game_3d_info = False
            close_btn.clicked.connect(_hide_info)
            outer_layout.addWidget(info_bar)
            outer_layout.addSpacing(4)

        # ── top stretch (push centre section towards middle) ──────────────────
        outer_layout.addStretch(2)

        # ── ASCII title ───────────────────────────────────────────────────────
        try:
            ascii_title = Figlet(font="ansi_shadow").renderText(script_base)
        except Exception:
            ascii_title = f"== {script_base} =="

        title_label = QLabel(ascii_title)
        title_label.setFont(QFont("Courier New", 10))
        title_label.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
        title_label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        title_label.setWordWrap(False)
        title_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        title_container = QWidget()
        title_container_layout = QVBoxLayout(title_container)
        title_container_layout.setContentsMargins(0, 0, 0, 0)
        title_container_layout.addWidget(title_label)

        title_scroll = QScrollArea(outer)
        title_scroll.setWidgetResizable(True)
        title_scroll.setWidget(title_container)
        title_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        title_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        title_scroll.setMaximumHeight(180)
        title_scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        outer_layout.addWidget(title_scroll)
        outer_layout.addSpacing(10)

        # ── badge row (type + last run) ───────────────────────────────────────
        badge_row = QHBoxLayout()
        badge_row.setContentsMargins(0, 0, 0, 0)
        badge_row.setSpacing(8)
        badge_row.addStretch(1)

        badge_lbl = QLabel("HTML" if html_game else "Python")
        badge_color = "#1e6fa8" if html_game else "#3a7d44"
        badge_lbl.setStyleSheet(
            f"background:{badge_color}; color:#fff; border-radius:4px;"
            "padding:1px 7px; font-size:11px; font-weight:bold;"
        )
        badge_lbl.setFixedHeight(20)
        badge_row.addWidget(badge_lbl)

        last_run_ts  = _load_last_run(config_path, path)
        last_run_lbl = QLabel(_format_last_run(last_run_ts))
        last_run_lbl.setStyleSheet("color: #888; font-size: 11px;")
        badge_row.addWidget(last_run_lbl)

        badge_row.addStretch(1)
        outer_layout.addLayout(badge_row)
        outer_layout.addSpacing(14)

        # ── status indicator ──────────────────────────────────────────────────
        status_row = QHBoxLayout()
        status_row.setContentsMargins(0, 0, 0, 0)
        status_row.addStretch(1)

        dot_lbl  = QLabel("●")
        text_lbl = QLabel("Ready")
        dot_lbl.setStyleSheet("color: #888; font-size: 14px;")
        text_lbl.setStyleSheet("color: #888; font-size: 12px;")
        status_row.addWidget(dot_lbl)
        status_row.addSpacing(4)
        status_row.addWidget(text_lbl)
        status_row.addStretch(1)
        outer_layout.addLayout(status_row)
        outer_layout.addSpacing(14)

        # ── buttons ───────────────────────────────────────────────────────────
        btn_run = QPushButton("Open in browser" if html_game else "▶  Run Game")
        btn_run.setFixedHeight(38)
        btn_run.setMinimumWidth(160)
        btn_run.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))

        btn_stop    = QPushButton("■  Stop")
        btn_restart = QPushButton("↺  Restart")
        for b in (btn_stop, btn_restart):
            b.setFixedHeight(34)
            b.setMinimumWidth(100)
            b.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            b.hide()

        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(0, 0, 0, 0)
        btn_row.setSpacing(8)
        btn_row.addStretch(1)
        btn_row.addWidget(btn_run)
        btn_row.addWidget(btn_restart)
        btn_row.addWidget(btn_stop)
        btn_row.addStretch(1)
        outer_layout.addLayout(btn_row)

        # ── bottom stretch ────────────────────────────────────────────────────
        outer_layout.addStretch(2)

        # ── collapsible logs ──────────────────────────────────────────────────
        logs_toggle = QPushButton("▼  Show logs")
        logs_toggle.setFixedHeight(24)
        logs_toggle.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        logs_toggle.setStyleSheet("text-align:left; padding-left:4px;")

        logs_frame = QFrame(outer)
        logs_frame.setFrameShape(QFrame.Shape.StyledPanel)
        logs_frame_layout = QVBoxLayout(logs_frame)
        logs_frame_layout.setContentsMargins(0, 0, 0, 0)
        logs_frame_layout.setSpacing(0)

        info_edit = QTextEdit()
        info_edit.setReadOnly(True)
        info_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        info_edit.setFont(QFont("Courier New", 10))
        info_edit.setFixedHeight(160)
        logs_frame_layout.addWidget(info_edit)
        logs_frame.hide()

        def _toggle_logs():
            if logs_frame.isHidden():
                logs_frame.show()
                logs_toggle.setText("▲  Hide logs")
            else:
                logs_frame.hide()
                logs_toggle.setText("▼  Show logs")
        logs_toggle.clicked.connect(_toggle_logs)

        outer_layout.addWidget(logs_toggle)
        outer_layout.addWidget(logs_frame)

        outer.setLayout(outer_layout)
        self.target_widget = outer if target_widget is None else target_widget
        outer._loader      = self

        # ── QProcess setup ────────────────────────────────────────────────────
        process = QProcess(outer)
        self._process = process

        def _set_idle():
            dot_lbl.setStyleSheet("color: #888; font-size: 14px;")
            text_lbl.setStyleSheet("color: #888; font-size: 12px;")
            text_lbl.setText("Ready")
            btn_run.show()
            btn_stop.hide()
            btn_restart.hide()

        def _set_running():
            dot_lbl.setStyleSheet("color: #2ecc71; font-size: 14px;")
            text_lbl.setStyleSheet("color: #2ecc71; font-size: 12px;")
            text_lbl.setText("Running")
            btn_run.hide()
            btn_stop.show()
            btn_restart.show()

        def _set_error():
            dot_lbl.setStyleSheet("color: #e74c3c; font-size: 14px;")
            text_lbl.setStyleSheet("color: #e74c3c; font-size: 12px;")
            text_lbl.setText("Error")
            btn_run.show()
            btn_stop.hide()
            btn_restart.hide()

        def _on_stdout():
            data = process.readAllStandardOutput().data()
            try:
                info_edit.append(data.decode("utf-8", errors="replace").rstrip())
            except Exception:
                pass

        def _on_stderr():
            data = process.readAllStandardError().data()
            try:
                info_edit.append(data.decode("utf-8", errors="replace").rstrip())
            except Exception:
                pass

        def _on_finished(exit_code: int, exit_status: QProcess.ExitStatus):
            info_edit.append(f"\nGame closed — exit code: {exit_code}")
            if exit_code == 0:
                _set_idle()
            else:
                _set_error()

        process.readyReadStandardOutput.connect(_on_stdout)
        process.readyReadStandardError.connect(_on_stderr)
        process.finished.connect(_on_finished)

        # ── launch logic ──────────────────────────────────────────────────────
        def _launch():
            if not os.path.exists(path):
                info_edit.append("File not found: " + path)
                if logs_frame.isHidden():
                    _toggle_logs()
                return

            now_ts = int(datetime.now().timestamp())
            _save_last_run(config_path, path, now_ts)
            last_run_lbl.setText(_format_last_run(now_ts))

            if html_game:
                webbrowser.open(f"file://{os.path.abspath(path)}")
                info_edit.append("Opened in system browser.")
                if logs_frame.isHidden():
                    _toggle_logs()
                return

            if process.state() != QProcess.ProcessState.NotRunning:
                return

            env = QProcessEnvironment.systemEnvironment()
            env.insert("SDL_RENDER_DRIVER",        "software")
            env.insert("SDL_RENDER_VSYNC",         "0")
            env.insert("SDL_HINT_RENDER_BATCHING", "0")
            process.setProcessEnvironment(env)
            process.start(sys.executable, [path])

            if process.waitForStarted(1000):
                info_edit.append("Game launched…")
                _set_running()
            else:
                info_edit.append("Failed to launch game.")
                _set_error()
                if logs_frame.isHidden():
                    _toggle_logs()

        def _stop():
            if process.state() != QProcess.ProcessState.NotRunning:
                process.terminate()
                if not process.waitForFinished(1000):
                    process.kill()
            _set_idle()

        def _restart():
            _stop()
            _launch()

        btn_run.clicked.connect(_launch)
        btn_stop.clicked.connect(_stop)
        btn_restart.clicked.connect(_restart)

        self._display   = info_edit
        self._container = outer
        self._scroll    = logs_frame

        return outer

    # ── called externally when tab is closed ──────────────────────────────────
    def stop_game(self):
        if self._process is not None and self._process.state() != QProcess.ProcessState.NotRunning:
            try:
                self._process.terminate()
                if not self._process.waitForFinished(1000):
                    self._process.kill()
            except Exception:
                pass

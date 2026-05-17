
from PyQt6 import QtWidgets, QtCore
from PyQt6.QtWidgets import (
    QSizePolicy, QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
)
from PyQt6.QtCore import Qt


class _ErrorOverlay(QFrame):
    """Floating overlay shown in the bottom-right corner of the terminal
    when a command exits with a non-zero exit code."""

    _BTN_STYLE = """
        QPushButton {
            background: #2a3540;
            color: #d0dce6;
            border: 1px solid #4a6070;
            border-radius: 3px;
            font-size: 10px;
            padding: 1px 6px;
        }
        QPushButton:hover   { background: #374d5e; }
        QPushButton:pressed { background: #1e2d38; }
    """

    def __init__(self, parent):
        super().__init__(parent)
        self.setObjectName("err_overlay")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet("""
            QFrame#err_overlay {
                background: rgba(28, 18, 18, 220);
                border: 1px solid #922b21;
                border-radius: 6px;
            }
        """)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 5, 8, 6)
        lay.setSpacing(5)

        self._lbl = QLabel("✗ exit 1")
        self._lbl.setStyleSheet(
            "color: #e74c3c; font-size: 10px; font-weight: bold; background: transparent;"
        )
        lay.addWidget(self._lbl)

        row = QHBoxLayout()
        row.setSpacing(4)
        row.setContentsMargins(0, 0, 0, 0)
        self.btn_explain = QPushButton("⚠ Explain")
        self.btn_fix = QPushButton("🔧 Fix")
        for b in (self.btn_explain, self.btn_fix):
            b.setFixedHeight(20)
            b.setStyleSheet(self._BTN_STYLE)
        row.addWidget(self.btn_explain)
        row.addWidget(self.btn_fix)
        lay.addLayout(row)

        self.setFixedSize(152, 62)
        self.hide()

    def set_exit_code(self, code: int):
        self._lbl.setText(f"✗ exit {code}")


class TerminalWrapper(QtWidgets.QWidget):
    def __init__(self, console_widget, min_h=40, pref_h=300, parent=None):
        super().__init__(parent)
        self._console = console_widget
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._console)

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self._pref_h = pref_h
        self._overlay: _ErrorOverlay | None = None

        try:
            self._console.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        except Exception:
            pass

    # ── overlay helpers ───────────────────────────────────────────────────────

    def _get_overlay(self) -> _ErrorOverlay:
        if self._overlay is None:
            self._overlay = _ErrorOverlay(self)
        return self._overlay

    def _place_overlay(self):
        if self._overlay is not None:
            margin = 10
            x = self.width()  - self._overlay.width()  - margin
            y = self.height() - self._overlay.height() - margin
            self._overlay.move(max(0, x), max(0, y))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._overlay is not None and self._overlay.isVisible():
            self._place_overlay()

    def show_error_overlay(self, exit_code: int):
        ov = self._get_overlay()
        ov.set_exit_code(exit_code)
        self._place_overlay()
        ov.show()
        ov.raise_()

    def hide_error_overlay(self):
        if self._overlay is not None:
            self._overlay.hide()

    def set_error_callbacks(self, explain_fn, fix_fn):
        """Connect Explain / Fix buttons. Safe to call multiple times."""
        ov = self._get_overlay()
        for btn, fn in ((ov.btn_explain, explain_fn), (ov.btn_fix, fix_fn)):
            try:
                btn.clicked.disconnect()
            except Exception:
                pass
            btn.clicked.connect(fn)

    # ── size hints ────────────────────────────────────────────────────────────

    def sizeHint(self):
        return QtCore.QSize(self.width(), self._pref_h)

    def minimumSizeHint(self):
        return QtCore.QSize(0, self.minimumHeight())

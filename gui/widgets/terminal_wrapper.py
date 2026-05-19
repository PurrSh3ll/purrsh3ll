
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

        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(4)
        self._lbl = QLabel("✗ exit 1")
        self._lbl.setStyleSheet(
            "color: #e74c3c; font-size: 10px; font-weight: bold; background: transparent;"
        )
        header.addWidget(self._lbl)
        header.addStretch()
        self.btn_close = QPushButton("✕")
        self.btn_close.setFixedSize(16, 16)
        self.btn_close.setStyleSheet(
            "QPushButton { background: transparent; border: none; color: #666; font-size: 10px; }"
            "QPushButton:hover { color: #ccc; }"
        )
        self.btn_close.clicked.connect(self.hide)
        header.addWidget(self.btn_close)
        lay.addLayout(header)

        row = QHBoxLayout()
        row.setSpacing(4)
        row.setContentsMargins(0, 0, 0, 0)
        self.btn_explain = QPushButton("⚠ Explain")
        self.btn_fix = QPushButton("🔧 Fix")
        self.btn_analyze = QPushButton("🔍 Analyze")
        for b in (self.btn_explain, self.btn_fix, self.btn_analyze):
            b.setFixedHeight(20)
            b.setStyleSheet(self._BTN_STYLE)
        row.addWidget(self.btn_explain)
        row.addWidget(self.btn_fix)
        row.addWidget(self.btn_analyze)
        lay.addLayout(row)

        self.setFixedSize(226, 66)
        self.hide()

    def set_exit_code(self, code: int):
        self._lbl.setText(f"✗ exit {code}")


class _HintOverlay(QFrame):
    """One-shot hint shown bottom-left on the first terminal."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setObjectName("hint_overlay")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet("""
            QFrame#hint_overlay {
                background: rgba(20, 28, 36, 200);
                border: 1px solid #3a5068;
                border-radius: 5px;
            }
        """)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 5, 10, 5)
        lbl = QLabel("Type <b>pshelp</b> to see available tools")
        lbl.setStyleSheet("color: #8ab4cc; font-size: 11px; background: transparent;")
        lay.addWidget(lbl)
        self.adjustSize()
        self.hide()


class TerminalWrapper(QtWidgets.QWidget):

    _hint_shown = False  # show only once per app session

    def __init__(self, console_widget, min_h=40, pref_h=300, parent=None):
        super().__init__(parent)
        self._console = console_widget
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._console)

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self._pref_h = pref_h
        self._overlay: _ErrorOverlay | None = None
        self._hint: _HintOverlay | None = None

        try:
            self._console.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        except Exception:
            pass

        if not TerminalWrapper._hint_shown:
            TerminalWrapper._hint_shown = True
            self._hint = _HintOverlay(self)
            self._console.installEventFilter(self)
            # Show after the widget is painted for the first time
            QtCore.QTimer.singleShot(800, self._show_hint)

    # ── hint overlay ──────────────────────────────────────────────────────────

    def _show_hint(self):
        if self._hint is None:
            return
        self._hint.adjustSize()
        self._place_hint()
        self._hint.show()
        self._hint.raise_()

    def _place_hint(self):
        if self._hint is not None:
            margin = 10
            x = margin
            y = self.height() - self._hint.height() - margin
            self._hint.move(max(0, x), max(0, y))

    def _hide_hint(self):
        if self._hint is not None and self._hint.isVisible():
            self._hint.hide()
            try:
                self._console.removeEventFilter(self)
            except Exception:
                pass

    def eventFilter(self, obj, event):
        if obj is self._console and event.type() == QtCore.QEvent.Type.KeyPress:
            self._hide_hint()
        return False

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
        if self._hint is not None and self._hint.isVisible():
            self._place_hint()

    def show_error_overlay(self, exit_code: int):
        ov = self._get_overlay()
        ov.set_exit_code(exit_code)
        self._place_overlay()
        ov.show()
        ov.raise_()

    def hide_error_overlay(self):
        if self._overlay is not None:
            self._overlay.hide()

    def set_error_callbacks(self, explain_fn, fix_fn, analyze_fn=None):
        """Connect Explain / Fix / Analyze buttons. Safe to call multiple times."""
        ov = self._get_overlay()
        pairs = [(ov.btn_explain, explain_fn), (ov.btn_fix, fix_fn)]
        if analyze_fn is not None:
            pairs.append((ov.btn_analyze, analyze_fn))
        for btn, fn in pairs:
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

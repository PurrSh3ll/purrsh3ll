import os
import re
import json
import base64
from PyQt6.QtCore import Qt, QEvent, QTimer, QSize, QObject, QPoint
from PyQt6.QtGui import QAction, QKeySequence, QFont, QColor, QIcon, QCursor
from PyQt6.QtWidgets import (QApplication, QMenu, QToolButton, QPushButton, QWidget,
                              QHBoxLayout, QVBoxLayout, QLineEdit, QLabel, QDialog,
                              QComboBox, QInputDialog)
from QTermWidget import QTermWidget
from gui.widgets.terminal_wrapper import TerminalWrapper

class TerminalSetupMixin:
    def set_terminal(self):
        self.wrapper_to_console = {}
        self.terminal_fifos = {}
        self._setup_terminal_actions()
        self._setup_terminal_zsh_env()
        self._setup_corner_buttons()
        self.widgets["terminal_tabs"].tabCloseRequested.connect(self._close_terminal_tab)
        self.widgets["terminal_tabs"].currentChanged.connect(lambda _: self.refresh_terminal_paused_colors())
        self.widgets["terminal_layout"].addWidget(self.widgets["terminal_tabs"])
        self._add_new_terminal_tab()
        self._setup_terminal_event_filter()
        self._setup_tab_bar()

    def _get_active_terminal(self):
        idx = self.widgets["terminal_tabs"].currentIndex()
        if idx < 0:
            return None
        widget = self.widgets["terminal_tabs"].widget(idx)
        if widget is None:
            return None

        # Prefer the focused QTermWidget — handles split terminals correctly
        focused = QApplication.focusWidget()
        if focused is not None:
            w = focused
            while w is not None:
                if isinstance(w, QTermWidget):
                    return w
                w = w.parent()

        # Fallback: primary terminal for this tab
        term = self.wrapper_to_console.get(widget)
        if term is not None:
            return term
        try:
            return widget.findChild(QTermWidget)
        except Exception:
            return None

    def _copy_selection(self):
        term = self._get_active_terminal()
        if not term:
            return
        if hasattr(term, "copySelection"):
            try:
                term.copySelection()
                return
            except Exception:
                pass
        if hasattr(term, "copyClipboard"):
            try:
                term.copyClipboard()
            except Exception:
                pass

    def _paste_selection(self):
        term = self._get_active_terminal()
        if not term:
            return
        if hasattr(term, "pasteSelection"):
            try:
                term.pasteSelection()
                return
            except Exception:
                pass
        self._paste_clipboard()

    def _paste_clipboard(self):
        term = self._get_active_terminal()
        if not term:
            return
        if hasattr(term, "pasteClipboard"):
            try:
                term.pasteClipboard()
            except Exception:
                pass

    def _zoom_in(self):
        term = self._get_active_terminal()
        if not term:
            return
        if hasattr(term, "zoom"):
            try:
                term.zoom(1)
                return
            except Exception:
                pass
        try:
            current = term.getTerminalFont()
            f = QFont(current.family(), (current.pointSize() or 11) + 1)
            if hasattr(term, "setTerminalFont"):
                term.setTerminalFont(f)
        except Exception:
            pass

    def _zoom_out(self):
        term = self._get_active_terminal()
        if not term:
            return
        if hasattr(term, "zoom"):
            try:
                term.zoom(-1)
                return
            except Exception:
                pass
        try:
            current = term.getTerminalFont()
            new_size = max(6, (current.pointSize() or 11) - 1)
            f = QFont(current.family(), new_size)
            if hasattr(term, "setTerminalFont"):
                term.setTerminalFont(f)
        except Exception:
            pass

    def _zoom_reset(self):
        term = self._get_active_terminal()
        if not term:
            return
        if hasattr(term, "resetZoom"):
            try:
                term.resetZoom()
                return
            except Exception:
                pass
        try:
            base = QFont("Monospace", 11)
            if hasattr(term, "setTerminalFont"):
                term.setTerminalFont(base)
        except Exception:
            pass

    def _setup_terminal_actions(self):
        groupbox = self.widgets["terminal_groupbox"]

        self._act_copy_selection = QAction("Copy selection", groupbox)
        self._act_copy_selection.setShortcut(QKeySequence("Ctrl+Shift+C"))

        self._act_paste_selection = QAction("Paste selection", groupbox)
        self._act_paste_selection.setShortcut(QKeySequence("Shift+Insert"))

        self._act_paste_clipboard = QAction("Paste clipboard", groupbox)
        self._act_paste_clipboard.setShortcut(QKeySequence("Ctrl+Shift+V"))

        self._act_zoom_in = QAction("Zoom In", groupbox)
        self._act_zoom_in.setShortcut(QKeySequence("Ctrl++"))

        self._act_zoom_out = QAction("Zoom Out", groupbox)
        self._act_zoom_out.setShortcut(QKeySequence("Ctrl+-"))

        self._act_zoom_reset = QAction("Zoom Reset", groupbox)
        self._act_zoom_reset.setShortcut(QKeySequence("Ctrl+0"))

        self._act_copy_selection.triggered.connect(self._copy_selection)
        self._act_paste_selection.triggered.connect(self._paste_selection)
        self._act_paste_clipboard.triggered.connect(self._paste_clipboard)
        self._act_zoom_in.triggered.connect(self._zoom_in)
        self._act_zoom_out.triggered.connect(self._zoom_out)
        self._act_zoom_reset.triggered.connect(self._zoom_reset)

        for a in (self._act_copy_selection, self._act_paste_selection, self._act_paste_clipboard,
                  self._act_zoom_in, self._act_zoom_out, self._act_zoom_reset):
            groupbox.addAction(a)

    def _setup_terminal_zsh_env(self):
        _zdotdir = os.path.join(self.base_path, "appdata", "terminal_modules", "zdotdir")
        os.makedirs(_zdotdir, exist_ok=True)
        _term_start_abs = os.path.join(self.base_path, "appdata", "term_start.zsh")
        _zshrc_content = (
            "# PurrShell silent terminal init\n"
            "_purrsh_real=\"${REAL_ZDOTDIR:-$HOME}\"\n"
            "[[ -f \"$_purrsh_real/.zshrc\" ]] && ZDOTDIR=\"$_purrsh_real\" source \"$_purrsh_real/.zshrc\"\n"
            "unset _purrsh_real REAL_ZDOTDIR\n"
            f"source '{_term_start_abs}' >/dev/null 2>&1\n"
            "fc -p\n"
        )
        with open(os.path.join(_zdotdir, ".zshrc"), "w", encoding="utf-8") as _zf:
            _zf.write(_zshrc_content)
        _real_zdotdir = os.environ.get("ZDOTDIR", os.path.expanduser("~"))
        self._term_env = [f"{k}={v}" for k, v in os.environ.items()
                         if k not in ("ZDOTDIR", "REAL_ZDOTDIR")]
        self._term_env.append(f"ZDOTDIR={_zdotdir}")
        self._term_env.append(f"REAL_ZDOTDIR={_real_zdotdir}")

    def _setup_corner_buttons(self):
        btn_add_left = QPushButton()
        btn_add_left.setFixedSize(24, 24)
        btn_add_left.setToolTip("Add terminal tab")
        btn_add_left.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        btn_add_left.setIcon(self.get_icon("claude-icon.svg", QIcon()))
        btn_add_left.setIconSize(QSize(16, 16))
        btn_add_left.clicked.connect(lambda checked: self._open_agent_ai_tab())

        btn_plus_menu = QToolButton()
        btn_plus_menu.setFixedSize(12, 24)
        btn_plus_menu.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        btn_plus_menu.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        btn_plus_menu.setArrowType(Qt.ArrowType.DownArrow)
        _plus_menu = QMenu()
        _opt_action = QAction("options", btn_plus_menu)
        _opt_action.triggered.connect(self._show_terminal_options_dialog)
        _plus_menu.addAction(_opt_action)
        btn_plus_menu.setMenu(_plus_menu)

        btn_add_console = QPushButton("+")
        btn_add_console.setFixedSize(24, 24)
        btn_add_console.setToolTip("Add terminal tab")
        btn_add_console.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        btn_add_console.clicked.connect(lambda checked: self._add_new_terminal_tab(**self.console_args))

        wrapper = QWidget()
        wrapper_layout = QHBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(1)
        wrapper_layout.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        dropdown_button = self.widgets.get("dropdown_terminal_button")
        if dropdown_button:
            wrapper_layout.addWidget(dropdown_button)
        wrapper_layout.addWidget(btn_add_left)
        wrapper_layout.addWidget(btn_plus_menu)
        wrapper_layout.addWidget(btn_add_console)
        self.widgets["terminal_tabs"].setCornerWidget(wrapper)

        # Floating collapse button — parented to terminal_groupbox so it sits in the
        # groupbox title band above terminal_tabs (corner widget is at tabs y=0, so
        # parenting to tabs would clip the button at negative y).
        tabs = self.widgets["terminal_tabs"]
        groupbox = self.widgets["terminal_groupbox"]
        btn_collapse = QPushButton("▲", groupbox)
        btn_collapse.setFixedSize(wrapper.sizeHint().width(), 10)
        btn_collapse.setFlat(True)
        btn_collapse.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        btn_collapse.setToolTip("Collapse / expand")
        btn_collapse.setStyleSheet("QPushButton { font-size: 7px; padding: 0px; border: none; }")
        btn_collapse.show()

        _collapsed = [False]
        _saved_sizes = [None]

        def _toggle_collapse(checked=False):
            splitter = self.widgets.get("splitter_main")
            if splitter is None:
                return
            if not _collapsed[0]:
                # ▲ → maximize terminals: save current sizes, push splitter to top
                _saved_sizes[0] = splitter.sizes()
                total = sum(_saved_sizes[0])
                splitter.setSizes([0, total])
                _collapsed[0] = True
                btn_collapse.setText("▼")
            else:
                # ▼ → restore previous sizes
                if _saved_sizes[0]:
                    splitter.setSizes(_saved_sizes[0])
                _collapsed[0] = False
                btn_collapse.setText("▲")

        btn_collapse.clicked.connect(_toggle_collapse)

        def _reposition_collapse():
            cw = tabs.cornerWidget()
            if cw is None:
                return
            # Anchor left edge to btn_add_left (claude icon), not the full corner widget
            # so the button width is stable regardless of how many tabs are open.
            anchor = btn_add_left.mapTo(groupbox, QPoint(0, 0))
            cw_in_gb = cw.mapTo(groupbox, QPoint(0, 0))
            right_edge = cw_in_gb.x() + cw.width()
            btn_h = btn_collapse.height()
            btn_collapse.setFixedWidth(right_edge - anchor.x())
            btn_collapse.move(anchor.x(), cw_in_gb.y() - btn_h)
            btn_collapse.raise_()

        class _CornerWatcher(QObject):
            def eventFilter(self_, obj, event):
                if event.type() in (QEvent.Type.Resize, QEvent.Type.Show, QEvent.Type.Move):
                    QTimer.singleShot(0, _reposition_collapse)
                return False

        _watcher = _CornerWatcher(groupbox)
        groupbox.installEventFilter(_watcher)
        tabs.installEventFilter(_watcher)
        self._corner_watcher = _watcher
        QTimer.singleShot(100, _reposition_collapse)

        self.widgets["btn_add_console"] = btn_add_console
        self.widgets["btn_add_left"] = btn_add_left
        self.widgets["btn_plus_menu"] = btn_plus_menu
        self.widgets["btn_collapse_terminal"] = btn_collapse
        self.widgets["terminal_corner_wrapper"] = wrapper


    def _setup_terminal_event_filter(self):
        _self = self

        class TerminalEventFilter(QObject):
            def __init__(self, parent=None):
                super().__init__(parent)
                self._mapping = _self.wrapper_to_console

            def eventFilter(self, watched, event):
                if event.type() != QEvent.Type.Wheel:
                    return False
                if not (QApplication.keyboardModifiers() & Qt.KeyboardModifier.ControlModifier):
                    return False
                try:
                    for term in list(self._mapping.values()):
                        if term is watched or term.isAncestorOf(watched):
                            delta = event.angleDelta().y()
                            if delta > 0:
                                try:
                                    if hasattr(term, "zoom"):
                                        term.zoom(1)
                                        return True
                                except Exception:
                                    pass
                                _self._zoom_in()
                            elif delta < 0:
                                try:
                                    if hasattr(term, "zoom"):
                                        term.zoom(-1)
                                        return True
                                except Exception:
                                    pass
                                _self._zoom_out()
                            return True
                except Exception:
                    pass
                return False

        app_instance = QApplication.instance()
        if app_instance is not None:
            terminal_event_filter = TerminalEventFilter(parent=self.widgets["terminal_groupbox"])
            app_instance.installEventFilter(terminal_event_filter)

    def _setup_tab_bar(self):
        tabbar = self.widgets["terminal_tabs"].tabBar()
        tabbar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        try:
            if not getattr(type(self), "_tab_doubleclick_connected", False):
                tabbar.tabDoubleClicked.connect(self._rename_terminal_tab)
                type(self)._tab_doubleclick_connected = True
        except Exception:
            try:
                tabbar.tabDoubleClicked.connect(self._rename_terminal_tab)
            except Exception:
                pass
        tabbar.tabBarDoubleClicked.connect(self._rename_terminal_tab)
        tabbar.customContextMenuRequested.connect(self._on_tab_bar_context_menu)

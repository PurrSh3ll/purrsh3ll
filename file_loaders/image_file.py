import hashlib
import os
import stat
import subprocess
import threading

from PyQt6.QtCore import Qt, QEvent, QObject, QSize, QTimer
from PyQt6.QtGui import QFont, QMovie, QPixmap
from PyQt6.QtWidgets import (
    QApplication, QDialog, QDialogButtonBox, QFrame, QHBoxLayout,
    QLabel, QPushButton, QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

_EXIFTOOL = None
try:
    _et = subprocess.run(['exiftool', '-ver'], capture_output=True, text=True, timeout=3)
    if _et.returncode == 0:
        _EXIFTOOL = 'exiftool'
except Exception:
    pass

_EXIFTOOL_PRIORITY = [
    'DateTimeOriginal', 'CreateDate', 'ModifyDate',
    'GPSLatitude', 'GPSLongitude', 'GPSAltitude', 'GPSPosition',
    'Make', 'Model', 'LensModel',
    'ExposureTime', 'FNumber', 'ISO', 'FocalLength', 'Flash',
    'ImageWidth', 'ImageHeight', 'ColorSpace', 'BitsPerSample',
    'Software', 'Artist', 'Copyright',
]

_EXIFTOOL_SKIP = {
    'SourceFile', 'ExifToolVersion', 'FileName', 'Directory',
    'FileSize', 'FileModifyDate', 'FileAccessDate', 'FileInodeChangeDate',
    'FilePermissions', 'FileType', 'FileTypeExtension', 'MIMEType',
}

# Animated formats handled via QMovie
_ANIMATED_EXTS = {'gif', 'webp'}


class _TabPage(QWidget):
    def sizeHint(self):
        return QSize(0, 0)

    def minimumSizeHint(self):
        return QSize(0, 0)


class _CtrlScrollFilter(QObject):
    def __init__(self, zoom_in_cb, zoom_out_cb, parent=None):
        super().__init__(parent)
        self._zoom_in = zoom_in_cb
        self._zoom_out = zoom_out_cb

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.Wheel:
            if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
                if event.angleDelta().y() > 0:
                    self._zoom_in()
                else:
                    self._zoom_out()
                return True
        return False


class Image_file:

    def __init__(self):
        self._container = None
        self._current_path = None
        self._file_size_bytes = 0
        self._ext = ''

        # Original pixmap (full resolution)
        self._pixmap = None
        self._movie = None
        self._zoom = 1.0
        self._img_w = 0
        self._img_h = 0

        self._page_display = None
        self._scroll_area = None
        self._zoom_label = None

        self._exiftool_result = {}
        self._hash_result = {}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        self._current_path = path
        self._ext = os.path.splitext(path)[1].lstrip('.').lower()
        try:
            self._file_size_bytes = os.path.getsize(path)
        except Exception:
            pass

        outer = _TabPage(parent=parent.widgets['execution_tabs'])
        outer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)
        outer._loader = self
        self._container = outer

        self._start_exiftool(path)
        self._start_hash_computation(path)
        self._build_ui(outer_layout, path)

        return outer

    def cleanup(self, timeout_ms=100):
        try:
            if self._movie is not None:
                self._movie.stop()
                self._movie = None
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Background workers
    # ------------------------------------------------------------------

    def _start_exiftool(self, path):
        if _EXIFTOOL is None:
            self._exiftool_result = {'done': True, 'error': 'exiftool not found'}
            return

        def run():
            try:
                proc = subprocess.run(
                    [_EXIFTOOL, '-json', '-a', path],
                    capture_output=True, text=True, timeout=15,
                )
                if proc.returncode == 0:
                    import json
                    data = json.loads(proc.stdout)
                    self._exiftool_result['data'] = data[0] if data else {}
                else:
                    self._exiftool_result['error'] = proc.stderr.strip() or 'exiftool error'
            except Exception as e:
                self._exiftool_result['error'] = str(e)
            finally:
                self._exiftool_result['done'] = True

        threading.Thread(target=run, daemon=True).start()

    def _start_hash_computation(self, path):
        def compute():
            try:
                md5 = hashlib.md5()
                sha256 = hashlib.sha256()
                with open(path, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        md5.update(chunk)
                        sha256.update(chunk)
                self._hash_result['md5'] = md5.hexdigest()
                self._hash_result['sha256'] = sha256.hexdigest()
            except Exception as e:
                self._hash_result['error'] = str(e)
            finally:
                self._hash_result['done'] = True

        threading.Thread(target=compute, daemon=True).start()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self, layout, path):
        # ── Title bar ──────────────────────────────────────────────────
        title_bar = QWidget()
        title_bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        title_bar.setMinimumWidth(0)
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(8, 6, 8, 4)
        title_layout.setSpacing(8)

        filename = os.path.basename(path)
        title = QLabel(f"🖼  {filename}")
        f = QFont()
        f.setPointSize(12)
        f.setBold(True)
        title.setFont(f)
        title.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        title.setMinimumWidth(0)
        title_layout.addWidget(title)

        info_btn = QPushButton("ℹ  Info")
        info_btn.setFixedHeight(28)
        info_btn.setMinimumWidth(0)
        info_btn.setToolTip("Show file info, EXIF metadata and hashes")
        info_btn.clicked.connect(self._show_info_dialog)
        title_layout.addWidget(info_btn)

        open_btn = QPushButton("↗ Open in system viewer")
        open_btn.setFixedHeight(28)
        open_btn.setMinimumWidth(0)
        open_btn.setToolTip("Open with the system default image viewer (xdg-open)")
        open_btn.clicked.connect(lambda: subprocess.Popen(['xdg-open', path]))
        title_layout.addWidget(open_btn)

        layout.addWidget(title_bar)

        # ── Zoom toolbar ───────────────────────────────────────────────
        zoom_bar = QWidget()
        zoom_bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        zoom_bar.setMinimumWidth(0)
        zoom_layout = QHBoxLayout(zoom_bar)
        zoom_layout.setContentsMargins(8, 2, 8, 2)
        zoom_layout.setSpacing(6)

        zoom_out_btn = QPushButton("−")
        zoom_out_btn.setFixedSize(28, 28)
        zoom_out_btn.setToolTip("Zoom out  (Ctrl+Scroll)")
        zoom_out_btn.clicked.connect(self._zoom_out)
        zoom_layout.addWidget(zoom_out_btn)

        self._zoom_label = QLabel("100%")
        self._zoom_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._zoom_label.setMinimumWidth(50)
        zoom_layout.addWidget(self._zoom_label)

        zoom_in_btn = QPushButton("+")
        zoom_in_btn.setFixedSize(28, 28)
        zoom_in_btn.setToolTip("Zoom in  (Ctrl+Scroll)")
        zoom_in_btn.clicked.connect(self._zoom_in)
        zoom_layout.addWidget(zoom_in_btn)

        fit_btn = QPushButton("Fit")
        fit_btn.setFixedHeight(28)
        fit_btn.setMinimumWidth(0)
        fit_btn.setToolTip("Fit image to window")
        fit_btn.clicked.connect(self._zoom_fit)
        zoom_layout.addWidget(fit_btn)

        reset_btn = QPushButton("1:1")
        reset_btn.setFixedHeight(28)
        reset_btn.setMinimumWidth(0)
        reset_btn.setToolTip("Reset to original size (100%)")
        reset_btn.clicked.connect(self._zoom_reset)
        zoom_layout.addWidget(reset_btn)

        zoom_layout.addStretch()

        # Dimensions label — filled after pixmap is loaded
        self._dim_label = QLabel("")
        self._dim_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight)
        self._dim_label.setEnabled(False)
        zoom_layout.addWidget(self._dim_label)

        layout.addWidget(zoom_bar)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(sep)

        # ── Image display ──────────────────────────────────────────────
        self._scroll_area = QScrollArea()
        self._scroll_area.setWidgetResizable(False)
        self._scroll_area.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll_filter = _CtrlScrollFilter(self._zoom_in, self._zoom_out)
        self._scroll_area.viewport().installEventFilter(self._scroll_filter)

        self._page_display = QLabel()
        self._page_display.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._scroll_area.setWidget(self._page_display)

        layout.addWidget(self._scroll_area, stretch=1)

        # Load image
        if self._ext in _ANIMATED_EXTS:
            self._load_animated(path)
        else:
            self._load_static(path)

    def _load_static(self, path):
        px = QPixmap(path)
        if px.isNull():
            self._page_display.setText(
                f"❌ Cannot display image.\nFormat may be unsupported or file is corrupted."
            )
            return
        self._pixmap = px
        self._img_w = px.width()
        self._img_h = px.height()
        self._dim_label.setText(f"{self._img_w} × {self._img_h} px")
        self._apply_zoom()

    def _load_animated(self, path):
        movie = QMovie(path)
        if not movie.isValid():
            # Fallback to static
            self._load_static(path)
            return
        self._movie = movie
        self._page_display.setMovie(movie)
        movie.start()
        # Get dimensions once first frame is ready
        sz = movie.currentPixmap().size()
        if sz.isValid():
            self._img_w = sz.width()
            self._img_h = sz.height()
            self._dim_label.setText(f"{self._img_w} × {self._img_h} px")
            self._page_display.resize(sz)
        self._zoom_label.setText("—")  # Zoom disabled for animated

    # ------------------------------------------------------------------
    # Zoom
    # ------------------------------------------------------------------

    def _apply_zoom(self):
        if self._pixmap is None:
            return
        w = max(1, int(self._img_w * self._zoom))
        h = max(1, int(self._img_h * self._zoom))
        scaled = self._pixmap.scaled(
            w, h,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self._page_display.setPixmap(scaled)
        self._page_display.resize(scaled.size())
        self._zoom_label.setText(f"{int(self._zoom * 100)}%")

    def _zoom_in(self):
        if self._pixmap is None:
            return
        if self._zoom < 8.0:
            self._zoom = round(min(8.0, self._zoom + 0.25), 2)
            self._apply_zoom()

    def _zoom_out(self):
        if self._pixmap is None:
            return
        if self._zoom > 0.1:
            self._zoom = round(max(0.1, self._zoom - 0.25), 2)
            self._apply_zoom()

    def _zoom_fit(self):
        if self._pixmap is None or self._img_w == 0 or self._img_h == 0:
            return
        vp = self._scroll_area.viewport()
        vw, vh = vp.width(), vp.height()
        if vw <= 0 or vh <= 0:
            return
        scale_w = vw / self._img_w
        scale_h = vh / self._img_h
        self._zoom = round(min(scale_w, scale_h), 4)
        self._apply_zoom()

    def _zoom_reset(self):
        if self._pixmap is None:
            return
        self._zoom = 1.0
        self._apply_zoom()

    # ------------------------------------------------------------------
    # Info dialog
    # ------------------------------------------------------------------

    def _show_info_dialog(self):
        dlg = QDialog(self._container)
        dlg.setWindowTitle(f"Info — {os.path.basename(self._current_path)}")
        dlg.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.WindowCloseButtonHint |
            Qt.WindowType.WindowMinimizeButtonHint
        )
        dlg.resize(700, 620)

        dlg_layout = QVBoxLayout(dlg)
        dlg_layout.setContentsMargins(12, 12, 12, 8)
        dlg_layout.setSpacing(8)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(4, 4, 8, 4)
        content_layout.setSpacing(10)

        poll_timers = []

        self._build_dialog_file_info(content_layout)
        content_layout.addWidget(self._hsep())

        self._build_dialog_metadata(content_layout, poll_timers)
        content_layout.addWidget(self._hsep())

        self._build_dialog_hashes(content_layout, poll_timers)

        content_layout.addStretch()
        scroll.setWidget(content)
        dlg_layout.addWidget(scroll)

        close_btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_btn.rejected.connect(dlg.close)
        dlg_layout.addWidget(close_btn)

        dlg.finished.connect(lambda _: [t.stop() for t in poll_timers if t])
        dlg.show()

    # ------------------------------------------------------------------
    # Dialog sections
    # ------------------------------------------------------------------

    def _build_dialog_file_info(self, layout):
        layout.addWidget(self._section_header("File Info"))

        size = self._file_size_bytes
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 ** 2:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size / 1024 ** 2:.1f} MB"
        layout.addWidget(self._kv_row("Size", size_str))

        try:
            layout.addWidget(self._kv_row(
                "Permissions", stat.filemode(os.stat(self._current_path).st_mode)
            ))
        except Exception:
            pass

        if self._img_w and self._img_h:
            layout.addWidget(self._kv_row("Dimensions", f"{self._img_w} × {self._img_h} px"))

        layout.addWidget(self._kv_row("Format", self._ext.upper()))

        if self._ext in _ANIMATED_EXTS and self._movie is not None:
            fc = self._movie.frameCount()
            if fc > 0:
                layout.addWidget(self._kv_row("Frames", str(fc)))

    def _build_dialog_metadata(self, layout, poll_timers):
        layout.addWidget(self._section_header("Metadata (exiftool)"))

        if _EXIFTOOL is None:
            layout.addWidget(QLabel(
                "exiftool not found — install: sudo apt install libimage-exiftool-perl"
            ))
            return

        status_lbl = QLabel("loading...")
        status_lbl.setEnabled(False)
        layout.addWidget(status_lbl)

        meta_container = QWidget()
        meta_layout = QVBoxLayout(meta_container)
        meta_layout.setContentsMargins(0, 0, 0, 0)
        meta_layout.setSpacing(1)
        layout.addWidget(meta_container)

        def populate(data):
            try:
                status_lbl.setVisible(False)
            except Exception:
                pass
            shown = set()
            rows = []
            for field in _EXIFTOOL_PRIORITY:
                if field in data and field not in _EXIFTOOL_SKIP:
                    rows.append((field, str(data[field])))
                    shown.add(field)
            for field, val in sorted(data.items()):
                if field not in shown and field not in _EXIFTOOL_SKIP:
                    rows.append((field, str(val)))
            if not rows:
                meta_layout.addWidget(QLabel("No metadata found"))
                return
            for key, val in rows:
                meta_layout.addWidget(self._kv_row(key, val))

        if self._exiftool_result.get('done'):
            if 'error' in self._exiftool_result:
                status_lbl.setText(f"Error: {self._exiftool_result['error']}")
            else:
                populate(self._exiftool_result.get('data', {}))
        else:
            poll = QTimer()
            poll.setInterval(100)

            def check():
                if not self._exiftool_result.get('done'):
                    return
                poll.stop()
                if 'error' in self._exiftool_result:
                    try:
                        status_lbl.setText(f"Error: {self._exiftool_result['error']}")
                    except Exception:
                        pass
                else:
                    populate(self._exiftool_result.get('data', {}))

            poll.timeout.connect(check)
            poll.start()
            poll_timers.append(poll)

    def _build_dialog_hashes(self, layout, poll_timers):
        layout.addWidget(self._section_header("Integrity"))

        md5_lbl = self._add_hash_row("MD5", "computing...", layout)
        sha256_lbl = self._add_hash_row("SHA256", "computing...", layout)

        if self._hash_result.get('done'):
            if 'error' in self._hash_result:
                md5_lbl.setText('error')
                sha256_lbl.setText('error')
            else:
                md5_lbl.setText(self._hash_result.get('md5', ''))
                sha256_lbl.setText(self._hash_result.get('sha256', ''))
        else:
            poll = QTimer()
            poll.setInterval(100)

            def check():
                if not self._hash_result.get('done'):
                    return
                poll.stop()
                try:
                    if 'error' in self._hash_result:
                        md5_lbl.setText('error')
                        sha256_lbl.setText('error')
                    else:
                        md5_lbl.setText(self._hash_result.get('md5', ''))
                        sha256_lbl.setText(self._hash_result.get('sha256', ''))
                except Exception:
                    pass

            poll.timeout.connect(check)
            poll.start()
            poll_timers.append(poll)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _section_header(self, text):
        lbl = QLabel(text)
        f = QFont()
        f.setBold(True)
        lbl.setFont(f)
        return lbl

    def _hsep(self):
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        return sep

    def _kv_row(self, key, val):
        row = QWidget()
        row_l = QHBoxLayout(row)
        row_l.setContentsMargins(0, 0, 0, 0)
        row_l.setSpacing(4)
        key_lbl = QLabel(f"{key}:")
        key_lbl.setEnabled(False)
        key_lbl.setFixedWidth(160)
        val_lbl = QLabel(str(val))
        val_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        val_lbl.setWordWrap(True)
        row_l.addWidget(key_lbl)
        row_l.addWidget(val_lbl, stretch=1)
        return row

    def _add_hash_row(self, label_text, initial_val, parent_layout):
        row = QWidget()
        row_l = QHBoxLayout(row)
        row_l.setContentsMargins(0, 0, 0, 0)
        row_l.setSpacing(6)
        key_lbl = QLabel(f"{label_text}:")
        key_lbl.setEnabled(False)
        key_lbl.setFixedWidth(60)
        val_lbl = QLabel(initial_val)
        val_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        mf = QFont("Monospace")
        mf.setPointSize(9)
        val_lbl.setFont(mf)
        copy_btn = QPushButton("📋")
        copy_btn.setFixedSize(24, 24)
        copy_btn.setToolTip(f"Copy {label_text} to clipboard")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(val_lbl.text()))
        row_l.addWidget(key_lbl)
        row_l.addWidget(val_lbl, stretch=1)
        row_l.addWidget(copy_btn)
        parent_layout.addWidget(row)
        return val_lbl

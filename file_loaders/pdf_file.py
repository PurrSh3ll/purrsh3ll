import os
import stat
import hashlib
import json
import subprocess
import threading

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QSizePolicy, QApplication, QFrame, QScrollArea,
    QDialog, QDialogButtonBox,
)
from PyQt6.QtCore import Qt, QTimer, QSize, QEvent, QObject
from PyQt6.QtGui import QFont, QPixmap, QImage

try:
    import fitz  # PyMuPDF
    _FITZ_OK = True
except ImportError:
    _FITZ_OK = False

_EXIFTOOL = None
try:
    _et = subprocess.run(['exiftool', '-ver'], capture_output=True, text=True, timeout=3)
    if _et.returncode == 0:
        _EXIFTOOL = 'exiftool'
except Exception:
    pass

# PDF object keys that indicate potentially malicious content
_IOC_KEYS = {
    '/JS':          'JavaScript code',
    '/JavaScript':  'JavaScript code',
    '/OpenAction':  'Automatic action on open',
    '/AA':          'Additional actions (auto-trigger)',
    '/Launch':      'Process launch action',
    '/SubmitForm':  'Form data submission to remote URL',
    '/GoToR':       'Remote file reference',
    '/GoToE':       'Embedded file reference',
    '/RichMedia':   'Rich media embed (Flash/video)',
    '/XFA':         'XFA form (complex, exploit-prone)',
}

# exiftool fields not useful to show (already in File Info or noise)
_EXIFTOOL_SKIP = {
    'SourceFile', 'ExifToolVersion', 'FileName', 'Directory',
    'FileSize', 'FileModifyDate', 'FileAccessDate', 'FileInodeChangeDate',
    'FilePermissions', 'FileType', 'FileTypeExtension', 'MIMEType',
    'PDFVersion', 'PageCount',
}

# exiftool fields to show first (OSINT priority)
_EXIFTOOL_PRIORITY = [
    'Author', 'Creator', 'Producer', 'Title', 'Subject', 'Keywords',
    'CreateDate', 'ModifyDate', 'MetadataDate',
    'XMPToolkit', 'DocumentID', 'InstanceID',
    'Tagged', 'Encrypted', 'UserAccess',
    'Language', 'PageLayout', 'PageMode',
]


class _TabPage(QWidget):
    """Tab page with zero sizeHint so it never forces the splitter to resize."""
    def sizeHint(self):
        return QSize(0, 0)

    def minimumSizeHint(self):
        return QSize(0, 0)


class _CtrlScrollFilter(QObject):
    """Event filter that intercepts Ctrl+Wheel and calls zoom callbacks."""

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


class Pdf_file:

    def __init__(self):
        self._container = None
        self._current_path = None
        self._file_size_bytes = 0

        self._doc = None
        self._page_num = 0
        self._page_count = 0
        self._zoom = 1.5

        self._page_display = None
        self._scroll_area = None
        self._prev_btn = None
        self._next_btn = None
        self._page_info_label = None
        self._zoom_label = None

        self._exiftool_result = {}
        self._hash_result = {}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        self._current_path = path
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

        if _FITZ_OK:
            try:
                self._doc = fitz.open(path)
                self._page_count = len(self._doc)
            except Exception:
                self._doc = None

        self._start_exiftool(path)
        self._start_hash_computation(path)
        self._build_ui(outer_layout, path)

        return outer

    def cleanup(self, timeout_ms=100):
        try:
            if self._doc:
                self._doc.close()
                self._doc = None
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Background computation
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
    # UI — tab contains page viewer
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
        title = QLabel(f"📄  {filename}")
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
        info_btn.setToolTip("Show file info, metadata, IoC scan and hashes")
        info_btn.clicked.connect(self._show_info_dialog)
        title_layout.addWidget(info_btn)

        open_btn = QPushButton("↗ Open in system viewer")
        open_btn.setFixedHeight(28)
        open_btn.setMinimumWidth(0)
        open_btn.setToolTip("Open with the system default PDF viewer (xdg-open)")
        open_btn.clicked.connect(lambda: subprocess.Popen(['xdg-open', path]))
        title_layout.addWidget(open_btn)

        layout.addWidget(title_bar)

        # ── Error states ───────────────────────────────────────────────
        if not _FITZ_OK:
            err = QLabel("PyMuPDF not installed — install: pip install pymupdf")
            err.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(err, stretch=1)
            return

        if self._doc is None:
            err = QLabel("Failed to open PDF — file may be corrupted or password-protected")
            err.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(err, stretch=1)
            return

        # ── Navigation bar ─────────────────────────────────────────────
        nav_bar = QWidget()
        nav_bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        nav_bar.setMinimumWidth(0)
        nav_layout = QHBoxLayout(nav_bar)
        nav_layout.setContentsMargins(8, 4, 8, 4)
        nav_layout.setSpacing(6)

        self._prev_btn = QPushButton("◀")
        self._prev_btn.setFixedSize(28, 28)
        self._prev_btn.setToolTip("Previous page")
        self._prev_btn.clicked.connect(self._prev_page)

        self._page_info_label = QLabel(f"1 / {self._page_count}")
        self._page_info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._page_info_label.setMinimumWidth(70)

        self._next_btn = QPushButton("▶")
        self._next_btn.setFixedSize(28, 28)
        self._next_btn.setToolTip("Next page")
        self._next_btn.clicked.connect(self._next_page)

        zoom_out_btn = QPushButton("−")
        zoom_out_btn.setFixedSize(28, 28)
        zoom_out_btn.setToolTip("Zoom out")
        zoom_out_btn.clicked.connect(self._zoom_out)

        self._zoom_label = QLabel(f"{int(self._zoom * 100)}%")
        self._zoom_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._zoom_label.setMinimumWidth(45)

        zoom_in_btn = QPushButton("+")
        zoom_in_btn.setFixedSize(28, 28)
        zoom_in_btn.setToolTip("Zoom in")
        zoom_in_btn.clicked.connect(self._zoom_in)

        nav_layout.addWidget(self._prev_btn)
        nav_layout.addWidget(self._page_info_label)
        nav_layout.addWidget(self._next_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(zoom_out_btn)
        nav_layout.addWidget(self._zoom_label)
        nav_layout.addWidget(zoom_in_btn)

        layout.addWidget(nav_bar)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(sep)

        # ── Page display ───────────────────────────────────────────────
        self._scroll_area = QScrollArea()
        self._scroll_area.setWidgetResizable(False)
        self._scroll_area.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll_filter = _CtrlScrollFilter(self._zoom_in, self._zoom_out)
        self._scroll_area.viewport().installEventFilter(self._scroll_filter)

        self._page_display = QLabel()
        self._page_display.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._page_display.setStyleSheet("background: #fff;")
        self._scroll_area.setWidget(self._page_display)

        layout.addWidget(self._scroll_area, stretch=1)

        self._update_nav_buttons()
        self._render_page()

    # ------------------------------------------------------------------
    # Page rendering
    # ------------------------------------------------------------------

    def _render_page(self):
        if self._doc is None or self._page_display is None:
            return
        try:
            page = self._doc[self._page_num]
            mat = fitz.Matrix(self._zoom, self._zoom)
            pix = page.get_pixmap(matrix=mat, alpha=False)
            img = QImage(
                pix.samples, pix.width, pix.height,
                pix.stride, QImage.Format.Format_RGB888
            )
            pixmap = QPixmap.fromImage(img)
            self._page_display.setPixmap(pixmap)
            self._page_display.resize(pixmap.size())
            self._page_info_label.setText(f"{self._page_num + 1} / {self._page_count}")
            self._zoom_label.setText(f"{int(self._zoom * 100)}%")
        except Exception:
            pass

    def _prev_page(self):
        if self._page_num > 0:
            self._page_num -= 1
            self._render_page()
            self._update_nav_buttons()

    def _next_page(self):
        if self._page_num < self._page_count - 1:
            self._page_num += 1
            self._render_page()
            self._update_nav_buttons()

    def _zoom_in(self):
        if self._zoom < 4.0:
            self._zoom = round(self._zoom + 0.25, 2)
            self._render_page()

    def _zoom_out(self):
        if self._zoom > 0.25:
            self._zoom = round(self._zoom - 0.25, 2)
            self._render_page()

    def _update_nav_buttons(self):
        if self._prev_btn:
            self._prev_btn.setEnabled(self._page_num > 0)
        if self._next_btn:
            self._next_btn.setEnabled(self._page_num < self._page_count - 1)

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
        dlg.resize(740, 700)

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

        self._build_dialog_structure(content_layout)
        content_layout.addWidget(self._hsep())

        self._build_dialog_urls(content_layout)
        content_layout.addWidget(self._hsep())

        self._build_dialog_ioc(content_layout)
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

        if self._doc is not None:
            meta = self._doc.metadata or {}

            pdf_format = meta.get('format', '?')
            layout.addWidget(self._kv_row("PDF Version", pdf_format))
            layout.addWidget(self._kv_row("Pages", str(self._page_count)))

            enc = meta.get('encryption')
            if enc:
                layout.addWidget(self._kv_row("Encryption", enc))
            else:
                layout.addWidget(self._kv_row("Encryption", "None"))

            # Document permissions (if encrypted)
            try:
                perms = self._doc.permissions
                if perms is not None:
                    perm_parts = []
                    if perms & fitz.PDF_PERM_PRINT:
                        perm_parts.append("print")
                    if perms & fitz.PDF_PERM_MODIFY:
                        perm_parts.append("modify")
                    if perms & fitz.PDF_PERM_COPY:
                        perm_parts.append("copy")
                    if perms & fitz.PDF_PERM_ANNOTATE:
                        perm_parts.append("annotate")
                    if perm_parts:
                        layout.addWidget(self._kv_row("Permissions (PDF)", ", ".join(perm_parts)))
            except Exception:
                pass

            # Metadata from PyMuPDF
            for field in ['title', 'author', 'subject', 'keywords', 'creator', 'producer',
                          'creationDate', 'modDate']:
                val = meta.get(field, '').strip()
                if val:
                    layout.addWidget(self._kv_row(field.capitalize(), val))

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
                meta_layout.addWidget(QLabel("No additional data"))
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

    def _build_dialog_structure(self, layout):
        layout.addWidget(self._section_header("Structure"))

        if self._doc is None:
            layout.addWidget(QLabel("PDF not loaded"))
            return

        # Table of contents / bookmarks
        toc = self._doc.get_toc()
        layout.addWidget(self._kv_row("Bookmarks (TOC)", str(len(toc)) + " entries"))
        if toc:
            for level, title, page in toc[:10]:
                prefix = "  " * (level - 1) + "└ "
                lbl = QLabel(f"{prefix}{title}  (p.{page})")
                lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                lbl.setEnabled(False if level > 1 else True)
                layout.addWidget(lbl)
            if len(toc) > 10:
                layout.addWidget(QLabel(f"  ... and {len(toc) - 10} more"))

        layout.addWidget(self._hsep())

        # Annotations per page
        total_annots = 0
        annot_types = {}
        for page in self._doc:
            for annot in page.annots():
                total_annots += 1
                t = annot.type[1] if annot.type else 'Unknown'
                annot_types[t] = annot_types.get(t, 0) + 1
        layout.addWidget(self._kv_row("Annotations", str(total_annots)))
        if annot_types:
            for t, count in sorted(annot_types.items()):
                layout.addWidget(self._kv_row(f"  {t}", str(count)))

        layout.addWidget(self._hsep())

        # Form fields
        try:
            widget_count = 0
            for page in self._doc:
                widget_count += len(list(page.widgets()))
            layout.addWidget(self._kv_row("Form fields", str(widget_count)))
        except Exception:
            pass

        # Embedded files
        try:
            emb_count = self._doc.embfile_count()
            layout.addWidget(self._kv_row("Embedded files", str(emb_count)))
            for i in range(emb_count):
                info = self._doc.embfile_info(i)
                name = info.get('name', f'file_{i}')
                size = info.get('size', 0)
                uname = info.get('uname', '')
                display = name if not uname or uname == name else f"{name} ({uname})"
                layout.addWidget(self._kv_row(f"  {display}", f"{size} bytes"))
        except Exception:
            pass

    def _build_dialog_urls(self, layout):
        layout.addWidget(self._section_header("Embedded URLs"))

        if self._doc is None:
            layout.addWidget(QLabel("PDF not loaded"))
            return

        urls = []
        for page_num, page in enumerate(self._doc):
            for link in page.get_links():
                if link.get('kind') == fitz.LINK_URI:
                    uri = link.get('uri', '').strip()
                    if uri:
                        urls.append((page_num + 1, uri))

        if not urls:
            layout.addWidget(QLabel("No embedded URLs found"))
            return

        layout.addWidget(QLabel(f"{len(urls)} URL(s) found:"))
        for page_num, uri in urls:
            row = self._kv_row(f"p.{page_num}", uri)
            layout.addWidget(row)

    def _build_dialog_ioc(self, layout):
        layout.addWidget(self._section_header("IoC Scan"))

        if self._doc is None:
            layout.addWidget(QLabel("PDF not loaded"))
            return

        findings = self._scan_ioc()

        if not findings:
            clean = QLabel("✓  No suspicious PDF keys detected")
            layout.addWidget(clean)
            return

        summary = QLabel(f"⚠  {len(findings)} suspicious indicator(s) found:")
        summary.setWordWrap(True)
        layout.addWidget(summary)

        for key, desc, xrefs in findings:
            count_str = f"({len(xrefs)} object{'s' if len(xrefs) > 1 else ''})"
            row = self._kv_row(key, f"{desc}  {count_str}")
            layout.addWidget(row)

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
    # IoC scanner
    # ------------------------------------------------------------------

    def _scan_ioc(self):
        """Scan PDF xref table for dangerous keys. Returns list of (key, desc, [xrefs])."""
        if self._doc is None:
            return []

        found = {}  # key → list of xref numbers
        try:
            xref_len = self._doc.xref_length()
            for xref in range(1, xref_len):
                try:
                    obj_str = self._doc.xref_object(xref, compressed=False)
                    for key in _IOC_KEYS:
                        if key in obj_str:
                            found.setdefault(key, []).append(xref)
                except Exception:
                    continue
        except Exception:
            pass

        return [
            (key, _IOC_KEYS[key], xrefs)
            for key, xrefs in found.items()
        ]

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
        key_lbl.setFixedWidth(140)
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

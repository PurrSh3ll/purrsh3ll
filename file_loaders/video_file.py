import os
import stat
import hashlib
import json
import subprocess
import threading

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QSlider, QSizePolicy, QApplication, QFrame, QScrollArea,
    QSplitter,
)
from PyQt6.QtCore import Qt, QTimer, QUrl
from PyQt6.QtGui import QFont

try:
    from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
    from PyQt6.QtMultimediaWidgets import QVideoWidget
    _QT_MEDIA_OK = True
except ImportError:
    _QT_MEDIA_OK = False

# exiftool: available on Kali, handles all video container formats and extracts
# GPS, encoder, device info, timestamps — essential for OSINT analysis.
_EXIFTOOL = None
try:
    result = subprocess.run(['exiftool', '-ver'], capture_output=True, text=True, timeout=3)
    if result.returncode == 0:
        _EXIFTOOL = 'exiftool'
except Exception:
    pass

# exiftool fields shown first in metadata panel — OSINT/forensics priority
_PRIORITY_FIELDS = [
    'GPSLatitude', 'GPSLongitude', 'GPSAltitude', 'GPSPosition',
    'CreateDate', 'ModifyDate', 'TrackCreateDate', 'DateTimeOriginal',
    'Encoder', 'Software', 'HandlerVendorID', 'Make', 'Model',
    'CompressorID', 'VideoCodecID', 'AudioCodecID',
    'MajorBrand', 'CompatibleBrands',
    'ImageWidth', 'ImageHeight', 'VideoFrameRate', 'Duration',
    'BitDepth', 'AudioSampleRate', 'AudioChannels',
    'Rotation', 'MatrixStructure',
    'FilePermissions', 'FileModifyDate', 'FileSize',
    'MIMEType', 'FileType',
]

# Fields to skip — filesystem noise already shown in File Info panel
_SKIP_FIELDS = {
    'SourceFile', 'ExifToolVersion', 'FileName', 'Directory',
    'FileSize', 'FileModifyDate', 'FileAccessDate', 'FileInodeChangeDate',
    'FilePermissions',
}


def _fmt_time(ms):
    if ms < 0:
        ms = 0
    s = ms // 1000
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m}:{s:02d}"


class Video_file:

    def __init__(self):
        self.target_widget = None
        self._container = None
        self._current_path = None
        self._file_size_bytes = 0

        self._player = None
        self._audio_output = None
        self._video_widget = None

        self._play_btn = None
        self._stop_btn = None
        self._seek_slider = None
        self._time_label = None
        self._volume_slider = None
        self._slider_dragging = False
        self._hash_poll_timer = None
        self._anomaly_label = None

        # populated by exiftool
        self._video_duration_sec = 0.0
        self._video_bitrate_kbps = 0

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        self._current_path = path

        outer = QWidget(parent=parent.widgets['execution_tabs'])
        outer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        outer._loader = self
        self.target_widget = outer if target_widget is None else target_widget
        self._container = outer

        self._build_ui(outer_layout, path, parent)

        return outer

    def cleanup(self, timeout_ms=100):
        try:
            ht = getattr(self, '_hash_poll_timer', None)
            if ht:
                ht.stop()
                self._hash_poll_timer = None
        except Exception:
            pass
        try:
            if self._player is not None:
                self._player.stop()
                self._player.setSource(QUrl())
        except Exception:
            pass

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self, layout, path, parent):
        # ── Title bar ──────────────────────────────────────────────────
        title_bar = QWidget()
        title_bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(8, 6, 8, 4)
        title_layout.setSpacing(8)

        filename = os.path.basename(path)
        title = QLabel(f"🎬  {filename}")
        f = QFont()
        f.setPointSize(12)
        f.setBold(True)
        title.setFont(f)
        title.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        title_layout.addWidget(title)

        open_btn = QPushButton("↗ Open in system player")
        open_btn.setFixedHeight(28)
        open_btn.setToolTip("Open with the system default video player (xdg-open)")
        open_btn.clicked.connect(lambda: subprocess.Popen(['xdg-open', path]))
        title_layout.addWidget(open_btn)

        layout.addWidget(title_bar)

        # ── Splitter: video (top) / info (bottom) ──────────────────────
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # Video widget
        if _QT_MEDIA_OK:
            self._video_widget = QVideoWidget()
            self._video_widget.setMinimumHeight(200)
            self._video_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            self._video_widget.setStyleSheet("background: #000;")
            splitter.addWidget(self._video_widget)
        else:
            placeholder = QLabel("QtMultimedia not available\nInstall: sudo apt install python3-pyqt6.qtmultimedia")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setMinimumHeight(120)
            splitter.addWidget(placeholder)

        # Bottom: player bar + info + hashes
        bottom = QWidget()
        bottom_layout = QVBoxLayout(bottom)
        bottom_layout.setContentsMargins(8, 4, 8, 8)
        bottom_layout.setSpacing(6)

        self._build_player_bar(bottom_layout, path)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        bottom_layout.addWidget(line)

        info_row = QWidget()
        info_row_layout = QHBoxLayout(info_row)
        info_row_layout.setContentsMargins(0, 0, 0, 0)
        info_row_layout.setSpacing(16)
        info_row_layout.addWidget(self._build_file_info_widget(path), stretch=1)
        info_row_layout.addWidget(self._build_metadata_widget(path), stretch=2)
        bottom_layout.addWidget(info_row)

        line2 = QFrame()
        line2.setFrameShape(QFrame.Shape.HLine)
        line2.setFrameShadow(QFrame.Shadow.Sunken)
        bottom_layout.addWidget(line2)

        self._build_hash_section(bottom_layout, path)
        bottom_layout.addStretch()

        splitter.addWidget(bottom)
        splitter.setSizes([400, 280])

        layout.addWidget(splitter)

        # ── Init media player ──────────────────────────────────────────
        if _QT_MEDIA_OK:
            self._player = QMediaPlayer()
            self._audio_output = QAudioOutput()
            self._audio_output.setVolume(self._volume_slider.value() / 100.0)
            self._player.setAudioOutput(self._audio_output)
            self._player.setVideoOutput(self._video_widget)
            self._player.setSource(QUrl.fromLocalFile(path))

            self._player.durationChanged.connect(self._on_duration_changed)
            self._player.positionChanged.connect(self._on_position_changed)
            self._player.playbackStateChanged.connect(self._on_state_changed)

    def _build_player_bar(self, layout, path):
        bar = QWidget()
        bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(0, 2, 0, 2)
        bar_layout.setSpacing(8)

        self._play_btn = QPushButton("▶  Play")
        self._play_btn.setFixedHeight(30)
        self._stop_btn = QPushButton("⏹")
        self._stop_btn.setFixedSize(30, 30)

        self._seek_slider = QSlider(Qt.Orientation.Horizontal)
        self._seek_slider.setRange(0, 0)
        self._seek_slider.setValue(0)

        self._time_label = QLabel("0:00 / 0:00")
        self._time_label.setMinimumWidth(95)
        self._time_label.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )

        vol_label = QLabel("🔊")
        self._volume_slider = QSlider(Qt.Orientation.Horizontal)
        self._volume_slider.setRange(0, 100)
        self._volume_slider.setValue(70)
        self._volume_slider.setMaximumWidth(80)
        self._volume_slider.setToolTip("Volume")

        bar_layout.addWidget(self._play_btn)
        bar_layout.addWidget(self._stop_btn)
        bar_layout.addWidget(self._seek_slider, stretch=1)
        bar_layout.addWidget(self._time_label)
        bar_layout.addWidget(vol_label)
        bar_layout.addWidget(self._volume_slider)
        layout.addWidget(bar)

        if not _QT_MEDIA_OK:
            self._play_btn.setEnabled(False)
            self._stop_btn.setEnabled(False)
            self._seek_slider.setEnabled(False)
            self._volume_slider.setEnabled(False)

        self._play_btn.clicked.connect(self._on_play_pause)
        self._stop_btn.clicked.connect(self._on_stop)
        self._seek_slider.sliderPressed.connect(self._on_slider_pressed)
        self._seek_slider.sliderReleased.connect(self._on_slider_released)
        self._volume_slider.valueChanged.connect(self._on_volume_changed)

    def _build_file_info_widget(self, path):
        widget = QWidget()
        vlayout = QVBoxLayout(widget)
        vlayout.setContentsMargins(0, 0, 0, 0)
        vlayout.setSpacing(3)

        hdr = QLabel("File Info")
        hf = QFont()
        hf.setBold(True)
        hdr.setFont(hf)
        vlayout.addWidget(hdr)

        rows = []
        try:
            size = os.path.getsize(path)
            self._file_size_bytes = size
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024 ** 2:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size / 1024 ** 2:.1f} MB"
            rows.append(("Size", size_str))
        except Exception:
            self._file_size_bytes = 0

        try:
            st = os.stat(path)
            rows.append(("Permissions", stat.filemode(st.st_mode)))
        except Exception:
            pass

        ext = os.path.splitext(path)[1].lstrip('.').upper() or "unknown"
        rows.append(("Extension", ext))

        # Populated later by exiftool (stored on instance for anomaly check)
        self._info_duration_label = None
        self._info_resolution_label = None
        self._info_codec_label = None
        self._info_fps_label = None
        self._info_bitrate_label = None

        for key, val in rows:
            vlayout.addWidget(self._kv_row(key, val))

        # Placeholder rows updated after exiftool finishes
        for attr, lbl in [
            ('_info_duration_label', 'Duration'),
            ('_info_resolution_label', 'Resolution'),
            ('_info_fps_label', 'FPS'),
            ('_info_codec_label', 'Codec'),
            ('_info_bitrate_label', 'Bitrate'),
        ]:
            lbl_widget = QLabel("—")
            lbl_widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            setattr(self, attr, lbl_widget)
            vlayout.addWidget(self._kv_row(lbl, lbl_widget))

        vlayout.addStretch()
        return widget

    def _build_metadata_widget(self, path):
        widget = QWidget()
        vlayout = QVBoxLayout(widget)
        vlayout.setContentsMargins(0, 0, 0, 0)
        vlayout.setSpacing(3)

        hdr = QLabel("Metadata (exiftool)")
        hf = QFont()
        hf.setBold(True)
        hdr.setFont(hf)
        vlayout.addWidget(hdr)

        if _EXIFTOOL is None:
            vlayout.addWidget(QLabel("exiftool not found — install with: sudo apt install libimage-exiftool-perl"))
            vlayout.addStretch()
            return widget

        self._meta_status = QLabel("loading...")
        self._meta_status.setEnabled(False)
        vlayout.addWidget(self._meta_status)

        self._meta_scroll = QScrollArea()
        self._meta_scroll.setWidgetResizable(True)
        self._meta_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._meta_scroll.setMaximumHeight(220)
        self._meta_inner = QWidget()
        self._meta_inner_layout = QVBoxLayout(self._meta_inner)
        self._meta_inner_layout.setContentsMargins(0, 0, 0, 0)
        self._meta_inner_layout.setSpacing(1)
        self._meta_scroll.setWidget(self._meta_inner)
        vlayout.addWidget(self._meta_scroll)

        # Load exiftool metadata in background thread with polling
        _result = {}

        def run_exiftool():
            try:
                proc = subprocess.run(
                    [_EXIFTOOL, '-json', '-a', path],
                    capture_output=True, text=True, timeout=15
                )
                if proc.returncode == 0:
                    data = json.loads(proc.stdout)
                    _result['data'] = data[0] if data else {}
                else:
                    _result['error'] = proc.stderr.strip() or 'exiftool error'
            except Exception as e:
                _result['error'] = str(e)
            finally:
                _result['done'] = True

        threading.Thread(target=run_exiftool, daemon=True).start()

        poll = QTimer()
        poll.setInterval(100)

        def check():
            if not _result.get('done'):
                return
            poll.stop()
            if 'error' in _result:
                self._meta_status.setText(f"Error: {_result['error']}")
                return
            self._populate_metadata(_result.get('data', {}))

        poll.timeout.connect(check)
        poll.start()
        self._meta_poll_timer = poll

        return widget

    def _populate_metadata(self, data):
        try:
            self._meta_status.setVisible(False)
        except Exception:
            pass

        # Update File Info panel with video-specific fields
        self._update_file_info_from_exiftool(data)

        # Build metadata rows: priority fields first, then rest
        shown = set()
        rows = []

        for field in _PRIORITY_FIELDS:
            if field in data and field not in _SKIP_FIELDS:
                rows.append((field, str(data[field])))
                shown.add(field)

        for field, val in sorted(data.items()):
            if field not in shown and field not in _SKIP_FIELDS:
                rows.append((field, str(val)))

        if not rows:
            try:
                self._meta_inner_layout.addWidget(QLabel("No metadata found"))
            except Exception:
                pass
            return

        for key, val in rows:
            # Highlight GPS fields
            key_display = key
            if 'GPS' in key:
                key_display = f"📍 {key}"
            row = self._kv_row(key_display, val)
            try:
                self._meta_inner_layout.addWidget(row)
            except Exception:
                pass

        try:
            self._meta_inner_layout.addStretch()
        except Exception:
            pass

        # Trigger anomaly check now that bitrate is known
        try:
            self._update_anomaly()
        except Exception:
            pass

    def _update_file_info_from_exiftool(self, data):
        try:
            dur = data.get('Duration', '')
            if dur:
                # exiftool returns "4.04 s" or "0:01:23"
                if isinstance(dur, (int, float)):
                    self._video_duration_sec = float(dur)
                    self._info_duration_label.setText(_fmt_time(int(dur * 1000)))
                elif 's' in str(dur):
                    sec = float(str(dur).replace('s', '').strip())
                    self._video_duration_sec = sec
                    self._info_duration_label.setText(_fmt_time(int(sec * 1000)))
                else:
                    self._info_duration_label.setText(str(dur))
        except Exception:
            pass

        try:
            w = data.get('ImageWidth') or data.get('SourceImageWidth')
            h = data.get('ImageHeight') or data.get('SourceImageHeight')
            if w and h:
                self._info_resolution_label.setText(f"{w} × {h}")
        except Exception:
            pass

        try:
            fps = data.get('VideoFrameRate')
            if fps:
                self._info_fps_label.setText(f"{fps}")
        except Exception:
            pass

        try:
            codec = data.get('CompressorID') or data.get('VideoCodecID') or data.get('FileType', '')
            if codec:
                self._info_codec_label.setText(str(codec))
        except Exception:
            pass

        try:
            # exiftool may report avg bitrate
            raw_br = data.get('AvgBitrate') or data.get('NominalBitrate') or ''
            if raw_br:
                # Normalize to kbps string
                self._info_bitrate_label.setText(str(raw_br))
                # Try to parse for anomaly check
                val = str(raw_br).lower().replace('kbps', '').replace('mbps', '').strip()
                try:
                    num = float(val.split()[0])
                    if 'mbps' in str(raw_br).lower():
                        self._video_bitrate_kbps = int(num * 1000)
                    else:
                        self._video_bitrate_kbps = int(num)
                except Exception:
                    pass
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Integrity section
    # ------------------------------------------------------------------

    def _build_hash_section(self, layout, path):
        widget = QWidget()
        vlayout = QVBoxLayout(widget)
        vlayout.setContentsMargins(0, 0, 0, 0)
        vlayout.setSpacing(4)

        hdr = QLabel("Integrity")
        hf = QFont()
        hf.setBold(True)
        hdr.setFont(hf)
        vlayout.addWidget(hdr)

        md5_lbl = self._add_hash_row("MD5", "computing...", vlayout)
        sha256_lbl = self._add_hash_row("SHA256", "computing...", vlayout)

        self._anomaly_label = QLabel("")
        self._anomaly_label.setWordWrap(True)
        vlayout.addWidget(self._anomaly_label)

        layout.addWidget(widget)

        _result = {}

        def compute():
            try:
                md5 = hashlib.md5()
                sha256 = hashlib.sha256()
                with open(path, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        md5.update(chunk)
                        sha256.update(chunk)
                _result['md5'] = md5.hexdigest()
                _result['sha256'] = sha256.hexdigest()
            except Exception as e:
                _result['error'] = str(e)
            finally:
                _result['done'] = True

        threading.Thread(target=compute, daemon=True).start()

        poll = QTimer()
        poll.setInterval(100)

        def check():
            if not _result.get('done'):
                return
            poll.stop()
            if 'error' in _result:
                md5_lbl.setText('error')
                sha256_lbl.setText('error')
            else:
                md5_lbl.setText(_result['md5'])
                sha256_lbl.setText(_result['sha256'])
            self._update_anomaly()

        poll.timeout.connect(check)
        poll.start()
        self._hash_poll_timer = poll

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

    def _update_anomaly(self):
        try:
            size = self._file_size_bytes
            duration = self._video_duration_sec
            bitrate = self._video_bitrate_kbps

            if duration > 0 and size > 0:
                actual_kbps = (size * 8) / (duration * 1000)
                if bitrate > 0:
                    ratio = actual_kbps / bitrate
                    if ratio > 1.5 or ratio < 0.5:
                        self._anomaly_label.setText(
                            f"⚠  Size/duration anomaly: actual {actual_kbps:.0f} kbps "
                            f"vs declared {bitrate} kbps (ratio {ratio:.2f}×) "
                            f"— may indicate embedded data"
                        )
                    else:
                        self._anomaly_label.setText(
                            f"✓  Size/duration: {actual_kbps:.0f} kbps "
                            f"(declared {bitrate} kbps)"
                        )
                else:
                    self._anomaly_label.setText(
                        f"Size/duration: {actual_kbps:.0f} kbps"
                    )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _kv_row(self, key, val_or_widget=None):
        row = QWidget()
        row_l = QHBoxLayout(row)
        row_l.setContentsMargins(0, 0, 0, 0)
        row_l.setSpacing(4)

        key_lbl = QLabel(f"{key}:")
        key_lbl.setEnabled(False)
        key_lbl.setFixedWidth(90)

        if isinstance(val_or_widget, QWidget):
            row_l.addWidget(key_lbl)
            row_l.addWidget(val_or_widget, stretch=1)
        else:
            val_lbl = QLabel(str(val_or_widget or ''))
            val_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            val_lbl.setWordWrap(True)
            row_l.addWidget(key_lbl)
            row_l.addWidget(val_lbl, stretch=1)

        return row

    # ------------------------------------------------------------------
    # Player callbacks
    # ------------------------------------------------------------------

    def _on_play_pause(self):
        if self._player is None:
            return
        state = self._player.playbackState()
        if state == QMediaPlayer.PlaybackState.PlayingState:
            self._player.pause()
        else:
            self._player.play()

    def _on_stop(self):
        if self._player is None:
            return
        self._player.stop()

    def _on_slider_pressed(self):
        self._slider_dragging = True

    def _on_slider_released(self):
        self._slider_dragging = False
        if self._player is not None:
            self._player.setPosition(self._seek_slider.value())

    def _on_volume_changed(self, value):
        if self._audio_output is not None:
            self._audio_output.setVolume(value / 100.0)

    def _on_duration_changed(self, duration_ms):
        self._seek_slider.setRange(0, duration_ms)
        total = _fmt_time(duration_ms)
        cur = _fmt_time(self._player.position() if self._player else 0)
        try:
            self._time_label.setText(f"{cur} / {total}")
        except Exception:
            pass

    def _on_position_changed(self, position_ms):
        if not self._slider_dragging:
            self._seek_slider.setValue(position_ms)
        dur = self._player.duration() if self._player else 0
        try:
            self._time_label.setText(f"{_fmt_time(position_ms)} / {_fmt_time(dur)}")
        except Exception:
            pass

    def _on_state_changed(self, state):
        try:
            if state == QMediaPlayer.PlaybackState.PlayingState:
                self._play_btn.setText("⏸  Pause")
            else:
                self._play_btn.setText("▶  Play")
        except Exception:
            pass

import os
import stat
import hashlib
import json
import subprocess
import threading

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QSlider, QSizePolicy, QApplication, QFrame, QScrollArea,
    QDialog, QDialogButtonBox,
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
        self._container = None
        self._current_path = None

        self._player = None
        self._audio_output = None
        self._video_widget = None
        self._play_btn = None
        self._stop_btn = None
        self._seek_slider = None
        self._time_label = None
        self._volume_slider = None
        self._slider_dragging = False

        # Background computation results (populated immediately on load)
        self._exiftool_result = {}  # {'done', 'data', 'error'}
        self._hash_result = {}      # {'done', 'md5', 'sha256', 'error'}

        # Parsed video properties (extracted from exiftool data)
        self._file_size_bytes = 0
        self._video_duration_sec = 0.0
        self._video_bitrate_kbps = 0
        self._video_bitrate_str = ''
        self._video_resolution = ''
        self._video_fps = ''
        self._video_codec = ''

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        self._current_path = path
        try:
            self._file_size_bytes = os.path.getsize(path)
        except Exception:
            pass

        outer = QWidget(parent=parent.widgets['execution_tabs'])
        outer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        outer.setMinimumWidth(0)
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)
        outer._loader = self
        self._container = outer

        self._build_ui(outer_layout, path)

        # Start background work immediately so data is ready when Info dialog opens
        self._start_exiftool(path)
        self._start_hash_computation(path)

        return outer

    def cleanup(self, timeout_ms=100):
        try:
            if self._player is not None:
                self._player.stop()
                self._player.setSource(QUrl())
        except Exception:
            pass

    # ------------------------------------------------------------------
    # UI construction — tab contains only video player
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
        title = QLabel(f"🎬  {filename}")
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
        info_btn.setToolTip("Show file info, metadata and hashes in a separate window")
        info_btn.clicked.connect(self._show_info_dialog)
        title_layout.addWidget(info_btn)

        open_btn = QPushButton("↗ Open in system player")
        open_btn.setFixedHeight(28)
        open_btn.setMinimumWidth(0)
        open_btn.setToolTip("Open with the system default video player (xdg-open)")
        open_btn.clicked.connect(lambda: subprocess.Popen(['xdg-open', path]))
        title_layout.addWidget(open_btn)

        layout.addWidget(title_bar)

        # ── Video widget (takes all available space) ───────────────────
        if _QT_MEDIA_OK:
            self._video_widget = QVideoWidget()
            self._video_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            self._video_widget.setStyleSheet("background: #000;")
            layout.addWidget(self._video_widget, stretch=1)
        else:
            placeholder = QLabel(
                "QtMultimedia not available\n"
                "Install: pip install PyQt6  (includes QtMultimedia)"
            )
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("background: #000; color: #888;")
            layout.addWidget(placeholder, stretch=1)

        # ── Player controls ────────────────────────────────────────────
        self._build_player_bar(layout, path)

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
        bar_layout.setContentsMargins(8, 4, 8, 6)
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

    # ------------------------------------------------------------------
    # Background computation
    # ------------------------------------------------------------------

    def _start_exiftool(self, path):
        if _EXIFTOOL is None:
            self._exiftool_result = {
                'done': True,
                'error': 'exiftool not found — install: sudo apt install libimage-exiftool-perl',
            }
            return

        def run():
            try:
                proc = subprocess.run(
                    [_EXIFTOOL, '-json', '-a', path],
                    capture_output=True, text=True, timeout=15
                )
                if proc.returncode == 0:
                    data = json.loads(proc.stdout)
                    d = data[0] if data else {}
                    self._exiftool_result['data'] = d
                    self._parse_video_properties(d)
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

    def _parse_video_properties(self, data):
        try:
            dur = data.get('Duration', '')
            if dur:
                if isinstance(dur, (int, float)):
                    self._video_duration_sec = float(dur)
                elif 's' in str(dur):
                    self._video_duration_sec = float(str(dur).replace('s', '').strip())
        except Exception:
            pass

        try:
            w = data.get('ImageWidth') or data.get('SourceImageWidth')
            h = data.get('ImageHeight') or data.get('SourceImageHeight')
            if w and h:
                self._video_resolution = f"{w} × {h}"
        except Exception:
            pass

        try:
            fps = data.get('VideoFrameRate')
            if fps:
                self._video_fps = str(fps)
        except Exception:
            pass

        try:
            codec = data.get('CompressorID') or data.get('VideoCodecID') or data.get('FileType', '')
            if codec:
                self._video_codec = str(codec)
        except Exception:
            pass

        try:
            raw_br = data.get('AvgBitrate') or data.get('NominalBitrate') or ''
            if raw_br:
                self._video_bitrate_str = str(raw_br)
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
        dlg.resize(720, 620)

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

        # File Info
        self._build_dialog_file_info(content_layout)

        sep1 = QFrame()
        sep1.setFrameShape(QFrame.Shape.HLine)
        sep1.setFrameShadow(QFrame.Shadow.Sunken)
        content_layout.addWidget(sep1)

        # Metadata
        self._build_dialog_metadata(content_layout, poll_timers)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setFrameShadow(QFrame.Shadow.Sunken)
        content_layout.addWidget(sep2)

        # Integrity
        self._build_dialog_hashes(content_layout, poll_timers)

        content_layout.addStretch()
        scroll.setWidget(content)
        dlg_layout.addWidget(scroll)

        close_btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_btn.rejected.connect(dlg.close)
        dlg_layout.addWidget(close_btn)

        def stop_timers():
            for t in poll_timers:
                try:
                    t.stop()
                except Exception:
                    pass

        dlg.finished.connect(lambda _: stop_timers())
        dlg.show()

    def _build_dialog_file_info(self, layout):
        hdr = QLabel("File Info")
        hf = QFont()
        hf.setBold(True)
        hdr.setFont(hf)
        layout.addWidget(hdr)

        path = self._current_path
        size = self._file_size_bytes
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 ** 2:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size / 1024 ** 2:.1f} MB"

        rows = [("Size", size_str)]

        try:
            rows.append(("Permissions", stat.filemode(os.stat(path).st_mode)))
        except Exception:
            pass

        rows.append(("Extension", os.path.splitext(path)[1].lstrip('.').upper() or "unknown"))

        # Video properties — already populated if exiftool finished
        if self._video_duration_sec > 0:
            rows.append(("Duration", _fmt_time(int(self._video_duration_sec * 1000))))
        if self._video_resolution:
            rows.append(("Resolution", self._video_resolution))
        if self._video_fps:
            rows.append(("FPS", self._video_fps))
        if self._video_codec:
            rows.append(("Codec", self._video_codec))
        if self._video_bitrate_str:
            rows.append(("Bitrate", self._video_bitrate_str))

        for key, val in rows:
            layout.addWidget(self._kv_row(key, val))

    def _build_dialog_metadata(self, layout, poll_timers):
        hdr = QLabel("Metadata (exiftool)")
        hf = QFont()
        hf.setBold(True)
        hdr.setFont(hf)
        layout.addWidget(hdr)

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
            for field in _PRIORITY_FIELDS:
                if field in data and field not in _SKIP_FIELDS:
                    rows.append((field, str(data[field])))
                    shown.add(field)
            for field, val in sorted(data.items()):
                if field not in shown and field not in _SKIP_FIELDS:
                    rows.append((field, str(val)))

            if not rows:
                meta_layout.addWidget(QLabel("No metadata found"))
                return

            for key, val in rows:
                key_display = f"📍 {key}" if 'GPS' in key else key
                meta_layout.addWidget(self._kv_row(key_display, val))

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
        hdr = QLabel("Integrity")
        hf = QFont()
        hf.setBold(True)
        hdr.setFont(hf)
        layout.addWidget(hdr)

        md5_lbl = self._add_hash_row("MD5", "computing...", layout)
        sha256_lbl = self._add_hash_row("SHA256", "computing...", layout)

        anomaly_lbl = QLabel("")
        anomaly_lbl.setWordWrap(True)
        layout.addWidget(anomaly_lbl)

        def update_anomaly():
            try:
                size = self._file_size_bytes
                duration = self._video_duration_sec
                bitrate = self._video_bitrate_kbps
                if duration > 0 and size > 0:
                    actual_kbps = (size * 8) / (duration * 1000)
                    if bitrate > 0:
                        ratio = actual_kbps / bitrate
                        if ratio > 1.5 or ratio < 0.5:
                            anomaly_lbl.setText(
                                f"⚠  Size/duration anomaly: actual {actual_kbps:.0f} kbps "
                                f"vs declared {bitrate} kbps (ratio {ratio:.2f}×) "
                                f"— may indicate embedded data"
                            )
                        else:
                            anomaly_lbl.setText(
                                f"✓  Size/duration: {actual_kbps:.0f} kbps "
                                f"(declared {bitrate} kbps)"
                            )
                    else:
                        anomaly_lbl.setText(f"Size/duration: {actual_kbps:.0f} kbps")
            except Exception:
                pass

        if self._hash_result.get('done'):
            if 'error' in self._hash_result:
                md5_lbl.setText('error')
                sha256_lbl.setText('error')
            else:
                md5_lbl.setText(self._hash_result.get('md5', ''))
                sha256_lbl.setText(self._hash_result.get('sha256', ''))
            update_anomaly()
        else:
            poll = QTimer()
            poll.setInterval(100)

            def check():
                if not self._hash_result.get('done'):
                    return
                poll.stop()
                if 'error' in self._hash_result:
                    try:
                        md5_lbl.setText('error')
                        sha256_lbl.setText('error')
                    except Exception:
                        pass
                else:
                    try:
                        md5_lbl.setText(self._hash_result.get('md5', ''))
                        sha256_lbl.setText(self._hash_result.get('sha256', ''))
                    except Exception:
                        pass
                update_anomaly()

            poll.timeout.connect(check)
            poll.start()
            poll_timers.append(poll)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

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

    def _kv_row(self, key, val_or_widget=None):
        row = QWidget()
        row_l = QHBoxLayout(row)
        row_l.setContentsMargins(0, 0, 0, 0)
        row_l.setSpacing(4)

        key_lbl = QLabel(f"{key}:")
        key_lbl.setEnabled(False)
        key_lbl.setFixedWidth(110)

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
        if self._player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self._player.pause()
        else:
            self._player.play()

    def _on_stop(self):
        if self._player is not None:
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
        cur = _fmt_time(self._player.position() if self._player else 0)
        try:
            self._time_label.setText(f"{cur} / {_fmt_time(duration_ms)}")
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

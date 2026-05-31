import io
import os
import stat
import hashlib
import json
import subprocess
import threading
import time
import wave

os.environ.setdefault("PYGAME_HIDE_SUPPORT_PROMPT", "1")

_SDL_DRIVER_ORDER = ["pipewire", "pulseaudio", ""]

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QSlider, QScrollArea, QSizePolicy, QApplication, QFrame,
    QDialog, QDialogButtonBox,
)
from PyQt6.QtCore import Qt, QTimer, QSize
from PyQt6.QtGui import QFont


class _TabPage(QWidget):
    """Tab page with zero sizeHint so it never forces the splitter to resize."""
    def sizeHint(self):
        return QSize(0, 0)

    def minimumSizeHint(self):
        return QSize(0, 0)

try:
    import pygame
    _PYGAME_OK = True
except ImportError:
    _PYGAME_OK = False

try:
    from mutagen import File as MutagenFile
    _MUTAGEN_OK = True
except ImportError:
    _MUTAGEN_OK = False

_EXIFTOOL = None
try:
    _et = subprocess.run(['exiftool', '-ver'], capture_output=True, text=True, timeout=3)
    if _et.returncode == 0:
        _EXIFTOOL = 'exiftool'
except Exception:
    pass


def _fmt_time(seconds):
    seconds = max(0, int(seconds))
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m}:{s:02d}"


_PRIORITY_TAGS = [
    "title", "artist", "album", "date", "comment", "description",
    "encoder", "encoded-by", "encodedby", "tool", "software",
    "author", "composer", "copyright", "lyrics", "website",
    "contact", "location", "performer", "organization", "isrc",
]

_EXIFTOOL_PRIORITY = [
    'LameVersion', 'LameEncoderSettings', 'VBRMethod', 'VBRQuality',
    'BitrateMode', 'EncoderDelay', 'EncoderPadding',
    'MPEGAudioVersion', 'AudioLayer', 'ChannelMode', 'ModeExtension',
    'CopyrightFlag', 'OriginalMedia', 'Emphasis',
    'ReplayGainPeakLevel', 'ReplayGainTrackGain',
    'VendorString',
    'Originator', 'OriginatorReference', 'DateTimeOriginal',
    'TimeReference', 'UMID', 'CodingHistory',
    'CreateDate', 'ModifyDate',
    'MIMEType', 'FileType',
]

_EXIFTOOL_SKIP = {
    'SourceFile', 'ExifToolVersion', 'FileName', 'Directory',
    'FileSize', 'FileModifyDate', 'FileAccessDate', 'FileInodeChangeDate',
    'FilePermissions', 'Duration', 'SampleRate', 'NumChannels',
    'BitsPerSample', 'AvgBitrate', 'NominalBitrate', 'AudioBitrate',
    'AudioSampleRate', 'AudioChannels', 'AudioBitsPerSample',
}

_FILE_INFO_EXIFTOOL_FIELDS = [
    'ChannelMode', 'BitrateMode', 'MPEGAudioVersion', 'AudioLayer',
    'LameVersion', 'LameEncoderSettings', 'VBRMethod', 'VBRQuality',
    'EncoderDelay', 'EncoderPadding', 'CopyrightFlag', 'OriginalMedia',
    'Emphasis', 'ReplayGainPeakLevel', 'ReplayGainTrackGain',
    'VendorString', 'Originator', 'OriginatorReference',
    'DateTimeOriginal', 'TimeReference', 'UMID', 'CodingHistory',
]


class Audio_file:

    def __init__(self):
        self.target_widget = None
        self._container = None
        self._current_path = None
        self._duration_sec = 0.0
        self._file_size_bytes = 0
        self._audio_bitrate = 0
        self._audio_duration = 0.0

        self._playing = False
        self._paused = False
        self._play_offset = 0.0
        self._play_start_ts = 0.0

        self._mixer_initialized = False
        self._poll_timer = None
        self._slider_dragging = False

        self._play_btn = None
        self._stop_btn = None
        self._seek_slider = None
        self._time_label = None
        self._volume_slider = None

        # Background computation results
        self._exiftool_result = {}  # {'done', 'data', 'error'}
        self._hash_result = {}      # {'done', 'md5', 'sha256', 'error'}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        self._current_path = path
        self._parent = parent
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
        self.target_widget = outer if target_widget is None else target_widget
        self._container = outer

        # Start background work immediately
        self._start_exiftool(path)
        self._start_hash_computation(path)

        self._build_ui(outer_layout, path)

        return outer

    def cleanup(self, timeout_ms=100):
        try:
            if self._poll_timer:
                self._poll_timer.stop()
                self._poll_timer = None
        except Exception:
            pass
        try:
            if self._mixer_initialized and (self._playing or self._paused):
                pygame.mixer.music.stop()
        except Exception:
            pass
        self._playing = False
        self._paused = False

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
    # UI — tab contains only player
    # ------------------------------------------------------------------

    def _build_ui(self, layout, path):
        # Title bar
        title_bar = QWidget()
        title_bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        title_bar.setMinimumWidth(0)
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(10, 8, 10, 4)
        title_layout.setSpacing(8)

        filename = os.path.basename(path)
        title = QLabel(f"🎵  {filename}")
        f = QFont()
        f.setPointSize(13)
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
        open_btn.setToolTip("Open with the system default audio player (xdg-open)")
        open_btn.clicked.connect(lambda: subprocess.Popen(['xdg-open', path]))
        title_layout.addWidget(open_btn)

        layout.addWidget(title_bar)

        # Player bar
        player_bar = QWidget()
        player_bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        player_layout = QHBoxLayout(player_bar)
        player_layout.setContentsMargins(10, 6, 10, 10)
        player_layout.setSpacing(8)

        self._play_btn = QPushButton("▶  Play")
        self._play_btn.setFixedHeight(32)
        self._stop_btn = QPushButton("⏹")
        self._stop_btn.setFixedSize(32, 32)

        self._seek_slider = QSlider(Qt.Orientation.Horizontal)
        self._seek_slider.setRange(0, 1000)
        self._seek_slider.setValue(0)

        self._time_label = QLabel("0:00 / 0:00")
        self._time_label.setMinimumWidth(95)
        self._time_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        vol_label = QLabel("🔊")
        self._volume_slider = QSlider(Qt.Orientation.Horizontal)
        self._volume_slider.setRange(0, 100)
        self._volume_slider.setValue(70)
        self._volume_slider.setMaximumWidth(80)
        self._volume_slider.setToolTip("Volume")

        player_layout.addWidget(self._play_btn)
        player_layout.addWidget(self._stop_btn)
        player_layout.addWidget(self._seek_slider, stretch=1)
        player_layout.addWidget(self._time_label)
        player_layout.addWidget(vol_label)
        player_layout.addWidget(self._volume_slider)
        layout.addWidget(player_bar)

        layout.addStretch()

        # Init mixer
        if _PYGAME_OK:
            if pygame.mixer.get_init():
                self._mixer_initialized = True
            else:
                for driver in _SDL_DRIVER_ORDER:
                    try:
                        if driver:
                            os.environ["SDL_AUDIODRIVER"] = driver
                        else:
                            os.environ.pop("SDL_AUDIODRIVER", None)
                        pygame.mixer.pre_init(44100, -16, 2, 8192)
                        pygame.mixer.init()
                        self._mixer_initialized = True
                        break
                    except Exception:
                        try:
                            pygame.mixer.quit()
                        except Exception:
                            pass

        if not self._mixer_initialized:
            self._play_btn.setEnabled(False)
            self._play_btn.setToolTip("Audio playback unavailable (pygame not initialized)")
            self._stop_btn.setEnabled(False)

        # NOTE: mutagen objects are falsy when tagless (e.g. plain WAV without ID3).
        # Must use `is not None` instead of truthiness.
        if _MUTAGEN_OK:
            try:
                audio = MutagenFile(path)
                if audio is not None and audio.info is not None:
                    self._duration_sec = float(audio.info.length)
            except Exception:
                pass

        self._update_time_label(0)

        self._play_btn.clicked.connect(self._on_play_pause)
        self._stop_btn.clicked.connect(self._on_stop)
        self._seek_slider.sliderPressed.connect(self._on_slider_pressed)
        self._seek_slider.sliderReleased.connect(self._on_slider_released)
        self._volume_slider.valueChanged.connect(self._on_volume_changed)

        self._poll_timer = QTimer()
        self._poll_timer.setInterval(200)
        self._poll_timer.timeout.connect(self._poll_position)

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
        dlg.resize(720, 680)

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

        self._build_dialog_raw_frames(content_layout)
        content_layout.addWidget(self._hsep())

        self._build_dialog_easy_tags(content_layout)
        content_layout.addWidget(self._hsep())

        self._build_dialog_exiftool(content_layout, poll_timers)
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

        path = self._current_path
        rows = []

        size = self._file_size_bytes
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 ** 2:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size / 1024 ** 2:.1f} MB"
        rows.append(("Size", size_str))

        if _MUTAGEN_OK:
            try:
                audio = MutagenFile(path)
                if audio is not None and audio.info is not None:
                    info = audio.info
                    dur = float(info.length)
                    self._audio_duration = dur
                    rows.append(("Duration", _fmt_time(dur)))
                    if hasattr(info, "bitrate") and info.bitrate:
                        self._audio_bitrate = info.bitrate // 1000
                        rows.append(("Bitrate", f"{self._audio_bitrate} kbps"))
                    if hasattr(info, "sample_rate"):
                        rows.append(("Sample rate", f"{info.sample_rate} Hz"))
                    if hasattr(info, "channels"):
                        ch = info.channels
                        ch_str = "Mono" if ch == 1 else "Stereo" if ch == 2 else f"{ch} ch"
                        rows.append(("Channels", ch_str))
                    rows.append(("Format", type(audio).__name__))
            except Exception:
                pass

        try:
            rows.append(("Permissions", stat.filemode(os.stat(path).st_mode)))
        except Exception:
            pass

        # exiftool technical fields — show if already done, else show from available data
        exiftool_data = self._exiftool_result.get('data', {})
        for field in _FILE_INFO_EXIFTOOL_FIELDS:
            if field in exiftool_data:
                rows.append((field, str(exiftool_data[field])))

        for key, val in rows:
            layout.addWidget(self._kv_row(key, val))

    def _build_dialog_raw_frames(self, layout):
        layout.addWidget(self._section_header("Raw Frames"))

        raw_rows = self._extract_raw_frames_info(self._current_path)
        if not raw_rows:
            layout.addWidget(QLabel("No raw frame data (format may not use ID3/FLAC blocks)"))
            return

        for key, val in raw_rows:
            layout.addWidget(self._kv_row(key, val))

    def _build_dialog_easy_tags(self, layout):
        layout.addWidget(self._section_header("Metadata Tags"))

        if not _MUTAGEN_OK:
            layout.addWidget(QLabel("mutagen library not installed"))
            return

        rows = []
        try:
            audio = MutagenFile(self._current_path, easy=True)
            if audio is not None:
                shown = set()
                for k in _PRIORITY_TAGS:
                    if k in audio:
                        v = audio[k]
                        val_str = "; ".join(str(x) for x in v) if isinstance(v, (list, tuple)) else str(v)
                        rows.append((k, val_str))
                        shown.add(k)
                for k, v in sorted(audio.items()):
                    if k not in shown:
                        val_str = "; ".join(str(x) for x in v) if isinstance(v, (list, tuple)) else str(v)
                        rows.append((k, val_str))
        except Exception as e:
            rows.append(("Error", str(e)))

        if not rows:
            layout.addWidget(QLabel("No metadata tags found"))
            return

        for key, val in rows:
            layout.addWidget(self._kv_row(key, val))

    def _build_dialog_exiftool(self, layout, poll_timers):
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
                meta_layout.addWidget(QLabel("No additional data from exiftool"))
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

        anomaly_lbl = QLabel("")
        anomaly_lbl.setWordWrap(True)
        layout.addWidget(anomaly_lbl)

        for indicator in self._compute_stego_indicators(self._current_path):
            lbl = QLabel(indicator)
            lbl.setWordWrap(True)
            layout.addWidget(lbl)

        def update_anomaly():
            try:
                duration = self._audio_duration
                bitrate = self._audio_bitrate
                size = self._file_size_bytes
                if duration > 0 and size > 0:
                    actual_kbps = (size * 8) / (duration * 1000)
                    if bitrate > 0:
                        ratio = actual_kbps / bitrate
                        if ratio > 1.5 or ratio < 0.5:
                            anomaly_lbl.setText(
                                f"⚠  Size/duration anomaly: actual {actual_kbps:.0f} kbps "
                                f"vs declared {bitrate} kbps (ratio {ratio:.2f}×) "
                                f"— may indicate embedded data or steganography"
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
    # Mutagen raw frames (synchronous)
    # ------------------------------------------------------------------

    def _extract_raw_frames_info(self, path):
        rows = []
        if not _MUTAGEN_OK:
            return rows
        try:
            audio = MutagenFile(path)
            if audio is None:
                return rows

            tags = audio.tags

            if hasattr(tags, 'vendor') and tags.vendor:
                rows.append(("Vendor string", tags.vendor))

            if hasattr(audio, 'pictures') and audio.pictures:
                for i, pic in enumerate(audio.pictures):
                    size = len(pic.data) if hasattr(pic, 'data') else 0
                    mime = getattr(pic, 'mime', '?')
                    rows.append((f"Cover art {i + 1}", f"{mime}, {size / 1024:.1f} KB"))

            if hasattr(audio, 'info') and hasattr(audio.info, 'md5_signature'):
                sig = audio.info.md5_signature
                if sig:
                    rows.append(("FLAC audio MD5", format(sig, '032x')))
                else:
                    rows.append(("FLAC audio MD5", "⚠ zero — audio may have been modified"))

            if tags is None:
                return rows

            if hasattr(tags, 'version'):
                v = tags.version
                rows.append(("ID3 Version", f"v{v[0]}.{v[1]}"))

            if hasattr(tags, '_size') and tags._size:
                rows.append(("ID3 Tag size", f"{tags._size / 1024:.1f} KB"))
            if hasattr(tags, '_padding') and tags._padding:
                rows.append(("ID3 Padding", f"{tags._padding} bytes"))

            for k in sorted(tags.keys()):
                if not k.startswith('APIC'):
                    continue
                frame = tags[k]
                size = len(frame.data) if hasattr(frame, 'data') else 0
                mime = getattr(frame, 'mime', '?')
                pic_type = getattr(frame, 'type', 0)
                desc = getattr(frame, 'desc', '') or f"type {pic_type}"
                rows.append((f"APIC ({desc})", f"{mime}, {size / 1024:.1f} KB"))

            for k in sorted(tags.keys()):
                if not k.startswith('PRIV'):
                    continue
                frame = tags[k]
                owner = getattr(frame, 'owner', k)
                size = len(frame.data) if hasattr(frame, 'data') else 0
                rows.append((f"PRIV ({owner})", f"{size} bytes"))

            for k in sorted(tags.keys()):
                if not k.startswith('GEOB'):
                    continue
                frame = tags[k]
                mime = getattr(frame, 'mime', '?')
                filename = getattr(frame, 'filename', '') or '?'
                size = len(frame.data) if hasattr(frame, 'data') else 0
                rows.append((f"GEOB ({filename})", f"{mime}, {size / 1024:.1f} KB"))

            for k in sorted(tags.keys()):
                if not (k.startswith('TXXX:') or k == 'TXXX'):
                    continue
                frame = tags[k]
                desc = getattr(frame, 'desc', k.replace('TXXX:', ''))
                text = getattr(frame, 'text', [''])[0] if hasattr(frame, 'text') else str(frame)
                rows.append((f"TXXX:{desc}", str(text)))

            for k in sorted(tags.keys()):
                if not k.startswith('UFID'):
                    continue
                frame = tags[k]
                owner = getattr(frame, 'owner', k)
                data_bytes = getattr(frame, 'data', b'')
                try:
                    val = data_bytes.decode('ascii').strip('\x00')
                except Exception:
                    val = data_bytes.hex()
                rows.append((f"UFID ({owner})", val))

            for prefix in ['WOAS', 'WORS', 'WOAF', 'WCOM', 'WPUB', 'WOAR']:
                if prefix in tags:
                    url = getattr(tags[prefix], 'url', str(tags[prefix]))
                    rows.append((prefix, url))

            for k in sorted(tags.keys()):
                if not (k.startswith('WXXX:') or k == 'WXXX'):
                    continue
                frame = tags[k]
                desc = getattr(frame, 'desc', k.replace('WXXX:', ''))
                url = getattr(frame, 'url', str(frame))
                rows.append((f"WXXX:{desc}", url))

            for frame_id in ['TDRC', 'TDRL', 'TDTG', 'TYER', 'TDAT', 'TLAN']:
                if frame_id in tags:
                    frame = tags[frame_id]
                    if hasattr(frame, 'text') and frame.text:
                        rows.append((frame_id, str(frame.text[0])))

        except Exception as e:
            rows.append(("Error (raw frames)", str(e)))

        return rows

    # ------------------------------------------------------------------
    # Steganography indicators (synchronous)
    # ------------------------------------------------------------------

    def _compute_stego_indicators(self, path):
        indicators = []
        if not _MUTAGEN_OK:
            return indicators
        try:
            audio = MutagenFile(path)
            if audio is None:
                return indicators

            tags = audio.tags
            file_size = self._file_size_bytes

            if tags is not None:
                if hasattr(tags, '_size') and tags._size and file_size > 0:
                    tag_ratio = tags._size / file_size
                    if tag_ratio > 0.10:
                        indicators.append(
                            f"⚠  Large ID3 header: {tags._size / 1024:.1f} KB "
                            f"({tag_ratio * 100:.1f}% of file) — unusual ratio"
                        )

                if hasattr(tags, '_padding') and tags._padding > 2048:
                    indicators.append(
                        f"⚠  Unusual ID3 padding: {tags._padding / 1024:.1f} KB "
                        f"— can conceal data"
                    )

                apic_keys = [k for k in tags.keys() if k.startswith('APIC')]
                apic_total = sum(
                    len(tags[k].data) for k in apic_keys if hasattr(tags[k], 'data')
                )
                if len(apic_keys) > 1:
                    indicators.append(f"⚠  Multiple embedded images: {len(apic_keys)} APIC frames")
                if apic_total > 2 * 1024 * 1024:
                    indicators.append(
                        f"⚠  Large embedded images: {apic_total / 1024 / 1024:.1f} MB total"
                    )

                geob_total = sum(
                    len(tags[k].data) for k in tags.keys()
                    if k.startswith('GEOB') and hasattr(tags[k], 'data')
                )
                if geob_total > 0:
                    indicators.append(
                        f"⚠  Embedded object (GEOB): {geob_total / 1024:.1f} KB "
                        f"— can contain any file type"
                    )

                priv_total = sum(
                    len(tags[k].data) for k in tags.keys()
                    if k.startswith('PRIV') and hasattr(tags[k], 'data')
                )
                if priv_total > 4096:
                    indicators.append(
                        f"⚠  Large PRIV payload: {priv_total / 1024:.1f} KB"
                    )

            if hasattr(audio, 'info') and hasattr(audio.info, 'md5_signature'):
                if audio.info.md5_signature == 0:
                    indicators.append(
                        "⚠  FLAC: audio MD5 signature is zero "
                        "— audio data may have been modified externally"
                    )

        except Exception:
            pass

        return indicators

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
        key_lbl.setFixedWidth(130)
        val_lbl = QLabel(str(val))
        val_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        val_lbl.setWordWrap(True)
        row_l.addWidget(key_lbl)
        row_l.addWidget(val_lbl, stretch=1)
        return row

    def _load_wav_from(self, path, pos_sec):
        """Return a BytesIO WAV buffer starting at pos_sec, or None on failure.

        pygame.mixer.music.play(start=X) does not support seeking in WAV files.
        Workaround: slice the WAV at the correct frame offset using the stdlib
        wave module, write the remaining frames into a BytesIO, and load that.
        """
        try:
            with wave.open(path, 'rb') as wf:
                framerate = wf.getframerate()
                nchannels = wf.getnchannels()
                sampwidth = wf.getsampwidth()
                nframes = wf.getnframes()
                start_frame = min(int(pos_sec * framerate), nframes)
                wf.setpos(start_frame)
                data = wf.readframes(nframes - start_frame)
            buf = io.BytesIO()
            with wave.open(buf, 'wb') as out:
                out.setnchannels(nchannels)
                out.setsampwidth(sampwidth)
                out.setframerate(framerate)
                out.writeframes(data)
            buf.seek(0)
            return buf
        except Exception:
            return None

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

    # ------------------------------------------------------------------
    # Player controls
    # ------------------------------------------------------------------

    def _on_play_pause(self):
        if not self._mixer_initialized:
            return
        try:
            if not self._playing and not self._paused:
                pygame.mixer.music.load(self._current_path)
                pygame.mixer.music.set_volume(self._volume_slider.value() / 100.0)
                pygame.mixer.music.play()
                self._play_offset = 0.0
                self._play_start_ts = time.monotonic()
                self._playing = True
                self._paused = False
                self._play_btn.setText("⏸  Pause")
                self._poll_timer.start()
            elif self._playing and not self._paused:
                pygame.mixer.music.pause()
                self._play_offset += time.monotonic() - self._play_start_ts
                self._paused = True
                self._playing = False
                self._play_btn.setText("▶  Play")
                self._poll_timer.stop()
            elif self._paused:
                pygame.mixer.music.unpause()
                self._play_start_ts = time.monotonic()
                self._playing = True
                self._paused = False
                self._play_btn.setText("⏸  Pause")
                self._poll_timer.start()
        except Exception:
            pass

    def _on_stop(self):
        if not self._mixer_initialized:
            return
        try:
            pygame.mixer.music.stop()
        except Exception:
            pass
        self._playing = False
        self._paused = False
        self._play_offset = 0.0
        self._play_btn.setText("▶  Play")
        self._poll_timer.stop()
        self._seek_slider.setValue(0)
        self._update_time_label(0)

    def _on_slider_pressed(self):
        self._slider_dragging = True

    def _on_slider_released(self):
        self._slider_dragging = False
        if not self._mixer_initialized or self._duration_sec <= 0:
            return
        pos_sec = self._seek_slider.value() / 1000.0 * self._duration_sec
        self._seek_to(pos_sec)

    def _seek_to(self, pos_sec):
        try:
            was_playing = self._playing
            was_paused = self._paused
            if not was_playing and not was_paused:
                return
            pygame.mixer.music.stop()

            # pygame.mixer.music.play(start=X) does not seek in WAV files —
            # use the wave module to slice the file from the target position.
            if self._current_path.lower().endswith('.wav'):
                buf = self._load_wav_from(self._current_path, pos_sec)
                if buf is not None:
                    pygame.mixer.music.load(buf, namehint='.wav')
                else:
                    pygame.mixer.music.load(self._current_path)
                    pos_sec = 0.0
                pygame.mixer.music.set_volume(self._volume_slider.value() / 100.0)
                pygame.mixer.music.play()
            else:
                pygame.mixer.music.load(self._current_path)
                pygame.mixer.music.set_volume(self._volume_slider.value() / 100.0)
                pygame.mixer.music.play(start=pos_sec)

            self._play_offset = pos_sec
            self._play_start_ts = time.monotonic()
            if was_paused and not was_playing:
                pygame.mixer.music.pause()
                self._playing = False
                self._paused = True
            else:
                self._playing = True
                self._paused = False
                self._poll_timer.start()
        except Exception:
            pass

    def _on_volume_changed(self, value):
        if self._mixer_initialized:
            try:
                pygame.mixer.music.set_volume(value / 100.0)
            except Exception:
                pass

    def _poll_position(self):
        if not self._playing:
            return
        try:
            if not pygame.mixer.music.get_busy():
                self._on_stop()
                return
            pos = self._play_offset + (time.monotonic() - self._play_start_ts)
            self._update_time_label(pos)
            if self._duration_sec > 0 and not self._slider_dragging:
                self._seek_slider.setValue(int(min(pos / self._duration_sec, 1.0) * 1000))
        except Exception:
            pass

    def _update_time_label(self, pos_sec):
        try:
            self._time_label.setText(
                f"{_fmt_time(pos_sec)} / {_fmt_time(self._duration_sec)}"
            )
        except Exception:
            pass

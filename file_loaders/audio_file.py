import os
import stat
import hashlib
import json
import subprocess
import threading
import time

os.environ.setdefault("PYGAME_HIDE_SUPPORT_PROMPT", "1")

_SDL_DRIVER_ORDER = ["pipewire", "pulseaudio", ""]

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QSlider, QScrollArea, QSizePolicy, QApplication, QFrame,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont

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


# Easy-mode tags shown first (OSINT priority)
_PRIORITY_TAGS = [
    "title", "artist", "album", "date", "comment", "description",
    "encoder", "encoded-by", "encodedby", "tool", "software",
    "author", "composer", "copyright", "lyrics", "website",
    "contact", "location", "performer", "organization", "isrc",
]

# exiftool fields shown first in the exiftool section — audio OSINT priority
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

# Fields to skip in exiftool section — already shown via mutagen
_EXIFTOOL_SKIP = {
    'SourceFile', 'ExifToolVersion', 'FileName', 'Directory',
    'FileSize', 'FileModifyDate', 'FileAccessDate', 'FileInodeChangeDate',
    'FilePermissions', 'Duration', 'SampleRate', 'NumChannels',
    'BitsPerSample', 'AvgBitrate', 'NominalBitrate', 'AudioBitrate',
    'AudioSampleRate', 'AudioChannels', 'AudioBitsPerSample',
}

# Technical fields placed in File Info panel (not Metadata)
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
        self._hash_poll_timer = None
        self._exiftool_poll_timer = None
        self._slider_dragging = False

        self._play_btn = None
        self._stop_btn = None
        self._seek_slider = None
        self._time_label = None
        self._volume_slider = None
        self._anomaly_label = None

        # Set by _build_* methods, populated by exiftool poll callback
        self._file_info_exiftool_layout = None
        self._file_info_exiftool_loading = None
        self._meta_exiftool_layout = None
        self._meta_exiftool_status = None
        self._exiftool_result = {}

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

        outer = QWidget(parent=parent.widgets['execution_tabs'])
        outer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)
        outer._loader = self
        self.target_widget = outer if target_widget is None else target_widget
        self._container = outer

        # Wrap in scroll area — content can be tall with all sections
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(10, 10, 10, 10)
        content_layout.setSpacing(8)

        self._start_exiftool(path)
        self._build_ui(content_layout, path)

        scroll.setWidget(content)
        outer_layout.addWidget(scroll)

        return outer

    def cleanup(self, timeout_ms=100):
        for attr in ('_poll_timer', '_hash_poll_timer', '_exiftool_poll_timer'):
            try:
                t = getattr(self, attr, None)
                if t:
                    t.stop()
                    setattr(self, attr, None)
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
    # Background — exiftool
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

    def _start_exiftool_poll(self):
        """Single poll timer that updates both File Info and Metadata when exiftool finishes."""
        poll = QTimer()
        poll.setInterval(100)

        def check():
            if not self._exiftool_result.get('done'):
                return
            poll.stop()
            self._exiftool_poll_timer = None
            if 'error' in self._exiftool_result:
                try:
                    self._meta_exiftool_status.setText(
                        f"Error: {self._exiftool_result['error']}"
                    )
                    if self._file_info_exiftool_loading:
                        self._file_info_exiftool_loading.setVisible(False)
                except Exception:
                    pass
            else:
                data = self._exiftool_result.get('data', {})
                self._populate_file_info_exiftool(data)
                self._populate_meta_exiftool(data)

        poll.timeout.connect(check)
        poll.start()
        self._exiftool_poll_timer = poll

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self, layout, path):
        filename = os.path.basename(path)

        title = QLabel(f"🎵  {filename}")
        f = QFont()
        f.setPointSize(13)
        f.setBold(True)
        title.setFont(f)
        layout.addWidget(title)

        self._build_player_bar(layout, path)

        sep1 = QFrame()
        sep1.setFrameShape(QFrame.Shape.HLine)
        sep1.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(sep1)

        info_row = QWidget()
        info_row_layout = QHBoxLayout(info_row)
        info_row_layout.setContentsMargins(0, 0, 0, 0)
        info_row_layout.setSpacing(16)
        info_row_layout.addWidget(self._build_file_info_widget(path), stretch=1)
        info_row_layout.addWidget(self._build_metadata_widget(path), stretch=2)
        layout.addWidget(info_row)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(sep2)

        self._build_hash_section(layout, path)
        layout.addStretch()

        # Start single exiftool poll after both panels are built
        if _EXIFTOOL:
            self._start_exiftool_poll()

    def _build_player_bar(self, layout, path):
        bar = QWidget()
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(0, 4, 0, 4)
        bar_layout.setSpacing(8)

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

        bar_layout.addWidget(self._play_btn)
        bar_layout.addWidget(self._stop_btn)
        bar_layout.addWidget(self._seek_slider, stretch=1)
        bar_layout.addWidget(self._time_label)
        bar_layout.addWidget(vol_label)
        bar_layout.addWidget(self._volume_slider)
        layout.addWidget(bar)

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

        for key, val in rows:
            vlayout.addWidget(self._kv_row(key, val))

        # Async exiftool technical fields — container populated by poll callback
        et_container = QWidget()
        et_layout = QVBoxLayout(et_container)
        et_layout.setContentsMargins(0, 0, 0, 0)
        et_layout.setSpacing(3)
        self._file_info_exiftool_layout = et_layout

        if _EXIFTOOL:
            loading = QLabel("exiftool: loading...")
            loading.setEnabled(False)
            et_layout.addWidget(loading)
            self._file_info_exiftool_loading = loading

        vlayout.addWidget(et_container)
        vlayout.addStretch()
        return widget

    def _build_metadata_widget(self, path):
        widget = QWidget()
        vlayout = QVBoxLayout(widget)
        vlayout.setContentsMargins(0, 0, 0, 0)
        vlayout.setSpacing(4)

        # ── Section 1: Easy tags ───────────────────────────────────────
        hdr1 = QLabel("Metadata Tags")
        hf = QFont()
        hf.setBold(True)
        hdr1.setFont(hf)
        vlayout.addWidget(hdr1)

        if not _MUTAGEN_OK:
            vlayout.addWidget(QLabel("mutagen library not installed"))
        else:
            easy_rows = []
            try:
                audio = MutagenFile(path, easy=True)
                if audio is not None:
                    shown = set()
                    for k in _PRIORITY_TAGS:
                        if k in audio:
                            v = audio[k]
                            val_str = "; ".join(str(x) for x in v) if isinstance(v, (list, tuple)) else str(v)
                            easy_rows.append((k, val_str))
                            shown.add(k)
                    for k, v in sorted(audio.items()):
                        if k not in shown:
                            val_str = "; ".join(str(x) for x in v) if isinstance(v, (list, tuple)) else str(v)
                            easy_rows.append((k, val_str))
            except Exception as e:
                easy_rows.append(("Error reading tags", str(e)))

            if not easy_rows:
                vlayout.addWidget(QLabel("No metadata tags found"))
            else:
                scroll1 = QScrollArea()
                scroll1.setWidgetResizable(True)
                scroll1.setFrameShape(QFrame.Shape.NoFrame)
                scroll1.setMaximumHeight(180)
                inner1 = QWidget()
                il1 = QVBoxLayout(inner1)
                il1.setContentsMargins(0, 0, 0, 0)
                il1.setSpacing(1)
                for key, val in easy_rows:
                    il1.addWidget(self._kv_row(key, val))
                il1.addStretch()
                scroll1.setWidget(inner1)
                vlayout.addWidget(scroll1)

            # ── Section 2: Raw Frames (synchronous) ───────────────────
            raw_rows = self._extract_raw_frames_info(path)
            if raw_rows:
                sep_r = QFrame()
                sep_r.setFrameShape(QFrame.Shape.HLine)
                sep_r.setFrameShadow(QFrame.Shadow.Sunken)
                vlayout.addWidget(sep_r)

                hdr2 = QLabel("Raw Frames")
                hf2 = QFont()
                hf2.setBold(True)
                hdr2.setFont(hf2)
                vlayout.addWidget(hdr2)

                scroll2 = QScrollArea()
                scroll2.setWidgetResizable(True)
                scroll2.setFrameShape(QFrame.Shape.NoFrame)
                scroll2.setMaximumHeight(160)
                inner2 = QWidget()
                il2 = QVBoxLayout(inner2)
                il2.setContentsMargins(0, 0, 0, 0)
                il2.setSpacing(1)
                for key, val in raw_rows:
                    il2.addWidget(self._kv_row(key, val))
                il2.addStretch()
                scroll2.setWidget(inner2)
                vlayout.addWidget(scroll2)

        # ── Section 3: exiftool (async) ────────────────────────────────
        if _EXIFTOOL:
            sep_e = QFrame()
            sep_e.setFrameShape(QFrame.Shape.HLine)
            sep_e.setFrameShadow(QFrame.Shadow.Sunken)
            vlayout.addWidget(sep_e)

            hdr3 = QLabel("Metadata (exiftool)")
            hf3 = QFont()
            hf3.setBold(True)
            hdr3.setFont(hf3)
            vlayout.addWidget(hdr3)

            et_status = QLabel("loading...")
            et_status.setEnabled(False)
            vlayout.addWidget(et_status)
            self._meta_exiftool_status = et_status

            scroll3 = QScrollArea()
            scroll3.setWidgetResizable(True)
            scroll3.setFrameShape(QFrame.Shape.NoFrame)
            scroll3.setMaximumHeight(200)
            inner3 = QWidget()
            il3 = QVBoxLayout(inner3)
            il3.setContentsMargins(0, 0, 0, 0)
            il3.setSpacing(1)
            scroll3.setWidget(inner3)
            vlayout.addWidget(scroll3)
            self._meta_exiftool_layout = il3

        return widget

    def _build_hash_section(self, layout, path):
        widget = QWidget()
        vlayout = QVBoxLayout(widget)
        vlayout.setContentsMargins(0, 0, 0, 0)
        vlayout.setSpacing(4)

        header = QLabel("Integrity")
        hf = QFont()
        hf.setBold(True)
        header.setFont(hf)
        vlayout.addWidget(header)

        md5_lbl = self._add_hash_row("MD5", "computing...", vlayout)
        sha256_lbl = self._add_hash_row("SHA256", "computing...", vlayout)

        self._anomaly_label = QLabel("")
        self._anomaly_label.setWordWrap(True)
        vlayout.addWidget(self._anomaly_label)

        # Steganography indicators from mutagen raw (synchronous)
        for indicator in self._compute_stego_indicators(path):
            lbl = QLabel(indicator)
            lbl.setWordWrap(True)
            vlayout.addWidget(lbl)

        layout.addWidget(widget)

        _result = {}

        def compute_hashes():
            try:
                md5 = hashlib.md5()
                sha256 = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        md5.update(chunk)
                        sha256.update(chunk)
                _result["md5"] = md5.hexdigest()
                _result["sha256"] = sha256.hexdigest()
            except Exception as e:
                _result["error"] = str(e)
            finally:
                _result["done"] = True

        threading.Thread(target=compute_hashes, daemon=True).start()

        poll = QTimer()
        poll.setInterval(100)

        def _check():
            if not _result.get("done"):
                return
            poll.stop()
            if "error" in _result:
                self._set_hash_label(md5_lbl, "error")
                self._set_hash_label(sha256_lbl, "error")
            else:
                self._set_hash_label(md5_lbl, _result["md5"])
                self._set_hash_label(sha256_lbl, _result["sha256"])
            self._update_anomaly()

        poll.timeout.connect(_check)
        poll.start()
        self._hash_poll_timer = poll

    # ------------------------------------------------------------------
    # exiftool populate callbacks
    # ------------------------------------------------------------------

    def _populate_file_info_exiftool(self, data):
        """Add technical exiftool fields to the File Info panel."""
        try:
            layout = self._file_info_exiftool_layout
            if layout is None:
                return

            # Remove loading label
            if self._file_info_exiftool_loading:
                try:
                    self._file_info_exiftool_loading.setVisible(False)
                except Exception:
                    pass

            rows = [(f, str(data[f])) for f in _FILE_INFO_EXIFTOOL_FIELDS if f in data]
            if not rows:
                return

            sep = QFrame()
            sep.setFrameShape(QFrame.Shape.HLine)
            sep.setFrameShadow(QFrame.Shadow.Sunken)
            layout.addWidget(sep)

            sub_hdr = QLabel("Encoder / Advanced")
            sf = QFont()
            sf.setBold(True)
            sf.setPointSize(8)
            sub_hdr.setFont(sf)
            sub_hdr.setEnabled(False)
            layout.addWidget(sub_hdr)

            for key, val in rows:
                layout.addWidget(self._kv_row(key, val))

        except Exception:
            pass

    def _populate_meta_exiftool(self, data):
        """Populate the exiftool metadata section in the Metadata panel."""
        try:
            layout = self._meta_exiftool_layout
            if layout is None:
                return

            try:
                self._meta_exiftool_status.setVisible(False)
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
                layout.addWidget(QLabel("No additional data from exiftool"))
                return

            for key, val in rows:
                layout.addWidget(self._kv_row(key, val))
            layout.addStretch()

        except Exception:
            pass

    # ------------------------------------------------------------------
    # Mutagen raw frames
    # ------------------------------------------------------------------

    def _extract_raw_frames_info(self, path):
        """Extract forensically relevant raw frame info via mutagen (non-easy mode)."""
        rows = []
        if not _MUTAGEN_OK:
            return rows
        try:
            audio = MutagenFile(path)
            if audio is None:
                return rows

            tags = audio.tags

            # FLAC/OGG: vendor string (exact encoder software + version)
            if hasattr(tags, 'vendor') and tags.vendor:
                rows.append(("Vendor string", tags.vendor))

            # FLAC: pictures (not in ID3 tags object)
            if hasattr(audio, 'pictures') and audio.pictures:
                for i, pic in enumerate(audio.pictures):
                    size = len(pic.data) if hasattr(pic, 'data') else 0
                    mime = getattr(pic, 'mime', '?')
                    rows.append((f"Cover art {i + 1}", f"{mime}, {size / 1024:.1f} KB"))

            # FLAC: audio MD5 signature (in stream info block)
            if hasattr(audio, 'info') and hasattr(audio.info, 'md5_signature'):
                sig = audio.info.md5_signature
                if sig:
                    rows.append(("FLAC audio MD5", format(sig, '032x')))
                else:
                    rows.append(("FLAC audio MD5", "⚠ zero — audio may have been modified"))

            if tags is None:
                return rows

            # ID3 version
            if hasattr(tags, 'version'):
                v = tags.version
                rows.append(("ID3 Version", f"v{v[0]}.{v[1]}"))

            # ID3 tag block size and padding
            if hasattr(tags, '_size') and tags._size:
                rows.append(("ID3 Tag size", f"{tags._size / 1024:.1f} KB"))
            if hasattr(tags, '_padding') and tags._padding:
                rows.append(("ID3 Padding", f"{tags._padding} bytes"))

            # APIC — embedded cover art
            for k in sorted(tags.keys()):
                if not k.startswith('APIC'):
                    continue
                frame = tags[k]
                size = len(frame.data) if hasattr(frame, 'data') else 0
                mime = getattr(frame, 'mime', '?')
                pic_type = getattr(frame, 'type', 0)
                desc = getattr(frame, 'desc', '') or f"type {pic_type}"
                rows.append((f"APIC ({desc})", f"{mime}, {size / 1024:.1f} KB"))

            # PRIV — private frames (owner identifier reveals software)
            for k in sorted(tags.keys()):
                if not k.startswith('PRIV'):
                    continue
                frame = tags[k]
                owner = getattr(frame, 'owner', k)
                size = len(frame.data) if hasattr(frame, 'data') else 0
                rows.append((f"PRIV ({owner})", f"{size} bytes"))

            # GEOB — general encapsulated object (arbitrary embedded file)
            for k in sorted(tags.keys()):
                if not k.startswith('GEOB'):
                    continue
                frame = tags[k]
                mime = getattr(frame, 'mime', '?')
                filename = getattr(frame, 'filename', '') or '?'
                size = len(frame.data) if hasattr(frame, 'data') else 0
                rows.append((f"GEOB ({filename})", f"{mime}, {size / 1024:.1f} KB"))

            # TXXX — user-defined text (custom software fields)
            for k in sorted(tags.keys()):
                if not (k.startswith('TXXX:') or k == 'TXXX'):
                    continue
                frame = tags[k]
                desc = getattr(frame, 'desc', k.replace('TXXX:', ''))
                text = getattr(frame, 'text', [''])[0] if hasattr(frame, 'text') else str(frame)
                rows.append((f"TXXX:{desc}", str(text)))

            # UFID — unique file identifier (MusicBrainz Track ID etc.)
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

            # URL frames — WOAS/WORS/WOAF/WCOM/WPUB/WOAR
            for prefix in ['WOAS', 'WORS', 'WOAF', 'WCOM', 'WPUB', 'WOAR']:
                if prefix in tags:
                    frame = tags[prefix]
                    url = getattr(frame, 'url', str(frame))
                    rows.append((prefix, url))

            # WXXX — user-defined URL
            for k in sorted(tags.keys()):
                if not (k.startswith('WXXX:') or k == 'WXXX'):
                    continue
                frame = tags[k]
                desc = getattr(frame, 'desc', k.replace('WXXX:', ''))
                url = getattr(frame, 'url', str(frame))
                rows.append((f"WXXX:{desc}", url))

            # ID3v2 date frames (multiple can coexist — discrepancy is suspicious)
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
        """Compute steganography indicators from mutagen raw. Returns list of warning strings."""
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
                # Large ID3 header relative to file size
                if hasattr(tags, '_size') and tags._size and file_size > 0:
                    tag_ratio = tags._size / file_size
                    if tag_ratio > 0.10:
                        indicators.append(
                            f"⚠  Large ID3 header: {tags._size / 1024:.1f} KB "
                            f"({tag_ratio * 100:.1f}% of file) — unusual ratio"
                        )

                # Unusual padding (common in steganography tools that inject after tags)
                if hasattr(tags, '_padding') and tags._padding > 2048:
                    indicators.append(
                        f"⚠  Unusual ID3 padding: {tags._padding / 1024:.1f} KB "
                        f"— can conceal data"
                    )

                # APIC (cover art) size and count
                apic_keys = [k for k in tags.keys() if k.startswith('APIC')]
                apic_total = sum(
                    len(tags[k].data) for k in apic_keys
                    if hasattr(tags[k], 'data')
                )
                if len(apic_keys) > 1:
                    indicators.append(f"⚠  Multiple embedded images: {len(apic_keys)} APIC frames")
                if apic_total > 2 * 1024 * 1024:
                    indicators.append(
                        f"⚠  Large embedded images: {apic_total / 1024 / 1024:.1f} MB total"
                    )

                # GEOB — arbitrary embedded file
                geob_total = sum(
                    len(tags[k].data) for k in tags.keys()
                    if k.startswith('GEOB') and hasattr(tags[k], 'data')
                )
                if geob_total > 0:
                    indicators.append(
                        f"⚠  Embedded object (GEOB): {geob_total / 1024:.1f} KB "
                        f"— can contain any file type"
                    )

                # PRIV with large payload
                priv_total = sum(
                    len(tags[k].data) for k in tags.keys()
                    if k.startswith('PRIV') and hasattr(tags[k], 'data')
                )
                if priv_total > 4096:
                    indicators.append(
                        f"⚠  Large PRIV payload: {priv_total / 1024:.1f} KB"
                    )

            # FLAC: zero MD5 signature means audio data was modified without updating header
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

    def _kv_row(self, key, val):
        row = QWidget()
        row_l = QHBoxLayout(row)
        row_l.setContentsMargins(0, 0, 0, 0)
        row_l.setSpacing(4)
        key_lbl = QLabel(f"{key}:")
        key_lbl.setEnabled(False)
        key_lbl.setFixedWidth(110)
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

    def _set_hash_label(self, label, value):
        try:
            label.setText(value)
        except Exception:
            pass

    def _update_anomaly(self):
        try:
            duration = self._audio_duration
            bitrate = self._audio_bitrate
            size = self._file_size_bytes
            if duration > 0 and size > 0:
                actual_kbps = (size * 8) / (duration * 1000)
                if bitrate > 0:
                    ratio = actual_kbps / bitrate
                    if ratio > 1.5 or ratio < 0.5:
                        self._anomaly_label.setText(
                            f"⚠  Size/duration anomaly: actual {actual_kbps:.0f} kbps "
                            f"vs declared {bitrate} kbps (ratio {ratio:.2f}×) "
                            f"— may indicate embedded data or steganography"
                        )
                    else:
                        self._anomaly_label.setText(
                            f"✓  Size/duration: {actual_kbps:.0f} kbps "
                            f"(declared {bitrate} kbps)"
                        )
                else:
                    self._anomaly_label.setText(f"Size/duration: {actual_kbps:.0f} kbps")
        except Exception:
            pass

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
            elapsed = time.monotonic() - self._play_start_ts
            pos = self._play_offset + elapsed
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

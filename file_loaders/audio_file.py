import os
import stat
import hashlib
import threading
import time

os.environ.setdefault("PYGAME_HIDE_SUPPORT_PROMPT", "1")

# SDL audio driver preference order — tried at mixer init time, not at import.
# pipewire: direct, fewest buffer stages, SDL 2.28+
# pulseaudio: goes through pipewire-pulse compat layer
# (empty): let SDL auto-detect
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


def _fmt_time(seconds):
    seconds = max(0, int(seconds))
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m}:{s:02d}"


# Metadata tag keys that are most relevant for OSINT/security analysis — shown first
_PRIORITY_TAGS = [
    "title", "artist", "album", "date", "comment", "description",
    "encoder", "encoded-by", "encodedby", "tool", "software",
    "author", "composer", "copyright", "lyrics", "website",
    "contact", "location", "performer", "organization", "isrc",
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
        self._play_offset = 0.0       # seconds already played before current play()
        self._play_start_ts = 0.0     # wall-clock time when play() was called

        self._mixer_initialized = False
        self._poll_timer = None
        self._slider_dragging = False

        self._play_btn = None
        self._stop_btn = None
        self._seek_slider = None
        self._time_label = None
        self._volume_slider = None
        self._anomaly_label = None

    # ------------------------------------------------------------------
    # Public interface (matches game_file.py pattern)
    # ------------------------------------------------------------------

    def load_file(self, path, parent=None, target_widget=None, threads_list=None):
        self._current_path = path
        self._parent = parent

        outer = QWidget(parent=parent.widgets['execution_tabs'])
        outer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)

        outer._loader = self
        self.target_widget = outer if target_widget is None else target_widget
        self._container = outer

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
            ht = getattr(self, "_hash_poll_timer", None)
            if ht:
                ht.stop()
                self._hash_poll_timer = None
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
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self, layout, path):
        filename = os.path.basename(path)

        # Title
        title = QLabel(f"🎵  {filename}")
        f = QFont()
        f.setPointSize(13)
        f.setBold(True)
        title.setFont(f)
        layout.addWidget(title)

        # Player bar
        self._build_player_bar(layout, path)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)

        # Info row: file info (left) + metadata tags (right)
        info_row = QWidget()
        info_row_layout = QHBoxLayout(info_row)
        info_row_layout.setContentsMargins(0, 0, 0, 0)
        info_row_layout.setSpacing(16)

        file_info_widget = self._build_file_info_widget(path)
        meta_widget = self._build_metadata_widget(path)
        info_row_layout.addWidget(file_info_widget, stretch=1)
        info_row_layout.addWidget(meta_widget, stretch=2)
        layout.addWidget(info_row)

        line2 = QFrame()
        line2.setFrameShape(QFrame.Shape.HLine)
        line2.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line2)

        # Hashes + anomaly check
        self._build_hash_section(layout, path)

        layout.addStretch()

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

        # Init pygame mixer. Try audio drivers in preference order so that the
        # best available driver is used without hard-failing if one is unavailable.
        # buffer=8192 gives ~186ms headroom for Qt's event loop (matches PipeWire
        # max-quantum from the VM fix config).
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

        # Duration from mutagen.
        # NOTE: mutagen objects are falsy when they have no tags (e.g. plain WAV
        # without ID3). Must check `is not None` instead of truthiness.
        if _MUTAGEN_OK:
            try:
                audio = MutagenFile(path)
                if audio is not None and audio.info is not None:
                    self._duration_sec = float(audio.info.length)
            except Exception:
                pass

        self._update_time_label(0)

        # Signals
        self._play_btn.clicked.connect(self._on_play_pause)
        self._stop_btn.clicked.connect(self._on_stop)
        self._seek_slider.sliderPressed.connect(self._on_slider_pressed)
        self._seek_slider.sliderReleased.connect(self._on_slider_released)
        self._volume_slider.valueChanged.connect(self._on_volume_changed)

        # Poll timer for position updates
        self._poll_timer = QTimer()
        self._poll_timer.setInterval(200)
        self._poll_timer.timeout.connect(self._poll_position)

    def _build_file_info_widget(self, path):
        widget = QWidget()
        vlayout = QVBoxLayout(widget)
        vlayout.setContentsMargins(0, 0, 0, 0)
        vlayout.setSpacing(3)

        header = QLabel("File Info")
        hf = QFont()
        hf.setBold(True)
        header.setFont(hf)
        vlayout.addWidget(header)

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
                # Use `is not None` — mutagen objects are falsy when tagless (e.g. WAV)
                if audio is not None and audio.info is not None:
                    info = audio.info
                    dur = float(info.length)
                    self._audio_duration = dur
                    rows.append(("Duration", _fmt_time(dur)))
                    if hasattr(info, "bitrate") and info.bitrate:
                        # mutagen returns bitrate in bps — convert to kbps
                        self._audio_bitrate = info.bitrate // 1000
                        rows.append(("Bitrate", f"{self._audio_bitrate} kbps"))
                    if hasattr(info, "sample_rate"):
                        rows.append(("Sample rate", f"{info.sample_rate} Hz"))
                    if hasattr(info, "channels"):
                        ch = info.channels
                        ch_str = "Mono" if ch == 1 else "Stereo" if ch == 2 else f"{ch} ch"
                        rows.append(("Channels", ch_str))
                    fmt = type(audio).__name__.replace("FLAC", "FLAC").replace("MP3", "MP3")
                    rows.append(("Format", fmt))
            except Exception:
                pass

        try:
            st = os.stat(path)
            rows.append(("Permissions", stat.filemode(st.st_mode)))
        except Exception:
            pass

        for key, val in rows:
            row_w = QWidget()
            row_l = QHBoxLayout(row_w)
            row_l.setContentsMargins(0, 0, 0, 0)
            row_l.setSpacing(4)
            key_lbl = QLabel(f"{key}:")
            key_lbl.setEnabled(False)
            key_lbl.setFixedWidth(90)
            val_lbl = QLabel(val)
            val_lbl.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            val_lbl.setWordWrap(True)
            row_l.addWidget(key_lbl)
            row_l.addWidget(val_lbl, stretch=1)
            vlayout.addWidget(row_w)

        vlayout.addStretch()
        return widget

    def _build_metadata_widget(self, path):
        widget = QWidget()
        vlayout = QVBoxLayout(widget)
        vlayout.setContentsMargins(0, 0, 0, 0)
        vlayout.setSpacing(3)

        header = QLabel("Metadata Tags")
        hf = QFont()
        hf.setBold(True)
        header.setFont(hf)
        vlayout.addWidget(header)

        if not _MUTAGEN_OK:
            vlayout.addWidget(QLabel("mutagen library not installed"))
            vlayout.addStretch()
            return widget

        rows = []
        try:
            audio = MutagenFile(path, easy=True)
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
            rows.append(("Error reading tags", str(e)))

        if not rows:
            vlayout.addWidget(QLabel("No metadata tags found"))
            vlayout.addStretch()
            return widget

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setMaximumHeight(220)

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(0, 0, 0, 0)
        inner_layout.setSpacing(1)

        for key, val in rows:
            row_w = QWidget()
            row_l = QHBoxLayout(row_w)
            row_l.setContentsMargins(0, 0, 0, 0)
            row_l.setSpacing(4)
            key_lbl = QLabel(f"{key}:")
            key_lbl.setEnabled(False)
            key_lbl.setFixedWidth(110)
            val_lbl = QLabel(val)
            val_lbl.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            val_lbl.setWordWrap(True)
            row_l.addWidget(key_lbl)
            row_l.addWidget(val_lbl, stretch=1)
            inner_layout.addWidget(row_w)

        inner_layout.addStretch()
        scroll.setWidget(inner)
        vlayout.addWidget(scroll)

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

        layout.addWidget(widget)

        # QTimer.singleShot cannot be called from threading.Thread — it has no
        # Qt event loop and the callback never fires. Instead: compute hashes in
        # a background thread writing to a shared dict, then poll from a QTimer
        # running in the main thread.
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
        self._hash_poll_timer = poll  # keep reference so GC doesn't collect it

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
                    self._anomaly_label.setText(
                        f"Size/duration: {actual_kbps:.0f} kbps"
                    )
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
                elapsed = time.monotonic() - self._play_start_ts
                self._play_offset += elapsed
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
                slider_val = int(min(pos / self._duration_sec, 1.0) * 1000)
                self._seek_slider.setValue(slider_val)
        except Exception:
            pass

    def _update_time_label(self, pos_sec):
        try:
            self._time_label.setText(
                f"{_fmt_time(pos_sec)} / {_fmt_time(self._duration_sec)}"
            )
        except Exception:
            pass

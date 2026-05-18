"""
voice_thread.py — Wake word → STT → AI command pipeline for PurrSh3ll.

Pipeline:
  idle  →  [wake word detected]  →  listening  →  [speech ends]
  →  processing  →  [AI response]  →  ready  →  [accepted/cancelled]  →  idle

States emitted via state_changed(str):
  "idle"        — waiting for wake word
  "listening"   — recording speech after wake word
  "processing"  — STT + AI running
  "ready"       — command generated, awaiting Accept/Cancel
  "error:<msg>" — something went wrong

VM-friendly design:
  - Callback-based audio capture into a Queue (no blocking reads → no xruns)
  - High latency mode for sounddevice (reduces buffer underruns on virtual audio)
  - Direct numpy transcription (no temp WAV file → no disk I/O)
  - Small sleep in wake word loop to yield CPU on vCPU-constrained VMs
"""

import logging
import os
import queue
import sys
import platform
import time

import numpy as np
from PyQt6.QtCore import QThread, pyqtSignal

logger = logging.getLogger(__name__)

# ── Audio constants ───────────────────────────────────────────────────────────
_SAMPLE_RATE   = 16_000   # Hz — required by OpenWakeWord and Whisper
_CHANNELS      = 1
_CHUNK_FRAMES  = 1_280    # 80 ms @ 16kHz — required chunk size for OpenWakeWord
_DTYPE         = "int16"

# ── VM-friendly audio settings ────────────────────────────────────────────────
# High latency gives the virtual audio driver more time to fill buffers,
# preventing xruns and choppy audio on VMs.
_AUDIO_LATENCY  = "high"   # 'low' | 'high' | float seconds (e.g. 0.2)
# Extra headroom: internal queue holds up to N chunks before dropping
_QUEUE_MAXSIZE  = 128

# ── VAD / silence detection ────────────────────────────────────────────────────
_VAD_ENERGY_THRESHOLD  = 200    # RMS energy below this → silence (lower for VM audio gain)
_VAD_SILENCE_SECONDS   = 1.8    # seconds of silence before we stop recording
_VAD_MIN_SPEECH_FRAMES = 6      # ignore very short noises (< ~480 ms)
_MAX_RECORD_SECONDS    = 30     # hard cap on recording length

# ── Wake word ─────────────────────────────────────────────────────────────────
_WAKEWORD_SCORE_THRESHOLD = 0.5  # min detection score

# ── CPU yield in wake word loop ───────────────────────────────────────────────
# On a VM, ONNX inference + audio callback compete for the same vCPUs.
# A tiny sleep after each chunk prediction lets the OS scheduler breathe.
_WAKEWORD_LOOP_SLEEP = 0.01   # 10 ms — negligible latency, big CPU relief


def _rms(chunk: np.ndarray) -> float:
    return float(np.sqrt(np.mean(chunk.astype(np.float32) ** 2)))


class VoiceThread(QThread):
    state_changed  = pyqtSignal(str)   # "idle" | "listening" | "processing" | "ready" | "confirming" | "error:..."
    command_ready  = pyqtSignal(str)   # generated shell command
    confirm_action = pyqtSignal(str)   # "accept" | "cancel" — voice confirmation

    def __init__(self, base_dir: str, parent=None):
        super().__init__(parent)
        self.base_dir         = base_dir
        self._running         = False
        self._exit_confirm    = False  # set by GUI to break out of confirm loop
        self._wakeword_model_name = "hey_jarvis"  # default; change via set_wakeword()

    def set_wakeword(self, name: str):
        """Set wake word model name (stem without extension, e.g. 'hey_jarvis')."""
        self._wakeword_model_name = name

    # ── Qt thread entry ───────────────────────────────────────────────────────

    def run(self):
        self._running = True
        try:
            self._pipeline()
        except Exception as e:
            logger.error("VoiceThread crashed: %s", e, exc_info=True)
            self.state_changed.emit(f"error:{e}")
        finally:
            self._running = False

    def stop(self):
        self._running = False

    def exit_confirm(self):
        """Called by GUI Cancel button to break out of the confirm loop."""
        self._exit_confirm = True

    # ── Main pipeline ─────────────────────────────────────────────────────────

    def _pipeline(self):
        import sounddevice as sd

        # Load wake word model
        try:
            ww_model = self._load_wakeword_model()
        except Exception as e:
            self.state_changed.emit(f"error:wake word model: {e}")
            return

        # Load Whisper model (tiny — fast, ~75 MB)
        try:
            stt_model = self._load_stt_model()
        except Exception as e:
            self.state_changed.emit(f"error:STT model: {e}")
            return

        self.state_changed.emit("idle")
        logger.info("VoiceThread: idle, waiting for wake word '%s'", self._wakeword_model_name)

        # ── Callback-based audio capture ──────────────────────────────────────
        # Using a queue + callback instead of blocking stream.read().
        # On VMs, blocking reads cause timing issues when the virtual audio
        # driver can't fill the buffer in time → xruns → choppy audio.
        # With a callback, the OS audio layer pushes data when ready;
        # we consume it from the queue at our own pace.
        audio_q: queue.Queue = queue.Queue(maxsize=_QUEUE_MAXSIZE)

        def _audio_callback(indata, frames, time_info, status):
            if status:
                logger.debug("sounddevice status: %s", status)
            try:
                audio_q.put_nowait(indata.copy())
            except queue.Full:
                pass  # drop oldest — we're behind; will recover next chunk

        with sd.InputStream(
            samplerate=_SAMPLE_RATE,
            channels=_CHANNELS,
            dtype=_DTYPE,
            blocksize=_CHUNK_FRAMES,
            latency=_AUDIO_LATENCY,
            callback=_audio_callback,
        ):
            while self._running:
                # ── Phase 1: wait for wake word ───────────────────────────────
                detected = self._wait_for_wakeword(audio_q, ww_model)
                if not detected:
                    break

                # ── Phase 2: record speech ────────────────────────────────────
                self.state_changed.emit("listening")
                logger.info("VoiceThread: wake word detected, recording...")
                audio_frames = self._record_speech(audio_q)
                if audio_frames is None:
                    self.state_changed.emit("idle")
                    continue

                # ── Phase 3: STT + AI ─────────────────────────────────────────
                self.state_changed.emit("processing")
                command = self._transcribe_and_generate(stt_model, audio_frames)
                if not command:
                    self.state_changed.emit("idle")
                    continue

                # ── Phase 4: emit command, then voice-confirm loop ────────────
                self.state_changed.emit("ready")
                self.command_ready.emit(command)

                # Wait for "Hey Jarvis" + "accept" / "cancel" via voice.
                # No AI needed — Whisper keyword check only.
                # Cooldown after command generation — flush model's internal
                # audio features so the voice used to generate the command
                # doesn't immediately re-trigger wake word detection.
                self._ww_cooldown(audio_q, ww_model, seconds=1.5)
                self._exit_confirm = False
                self.state_changed.emit("idle")
                while self._running and not self._exit_confirm:
                    detected = self._wait_for_wakeword(audio_q, ww_model)
                    if not detected:
                        break

                    self.state_changed.emit("confirming")
                    frames = self._record_speech(audio_q)
                    if frames is None:
                        self.state_changed.emit("idle")
                        continue

                    text = self._transcribe(stt_model, frames).lower()
                    if "accept" in text:
                        self.confirm_action.emit("accept")
                        break  # back to main wake word loop
                    elif "cancel" in text:
                        self.confirm_action.emit("cancel")
                        break  # back to main wake word loop
                    else:
                        # Neither word — cooldown then back to wake word listening
                        self._ww_cooldown(audio_q, ww_model, seconds=1.5)
                        self.state_changed.emit("idle")

                # After accept/cancel: flush queue, run cooldown (feed audio
                # to model without checking scores) so internal mel-spectrogram
                # features built up from "cancel"/"accept" speech drain out
                # before we re-enter wake word detection.
                self._ww_cooldown(audio_q, ww_model, seconds=1.5)
                self.state_changed.emit("idle")

        self.state_changed.emit("idle")

    # ── Wake word detection ───────────────────────────────────────────────────

    def _load_wakeword_model(self):
        import openwakeword
        paths = openwakeword.get_pretrained_model_paths()
        target = self._wakeword_model_name.lower()
        matched = [p for p in paths if target in os.path.basename(p).lower()]
        if not matched:
            available = [os.path.splitext(os.path.basename(p))[0] for p in paths]
            raise RuntimeError(
                f"Wake word model '{self._wakeword_model_name}' not found. "
                f"Available: {available}"
            )
        model_path = matched[0]
        logger.info("VoiceThread: loading wake word model: %s", model_path)
        from openwakeword import Model
        return Model(wakeword_model_paths=[model_path])

    def _ww_cooldown(self, audio_q: queue.Queue, ww_model, seconds: float = 1.5):
        """Drain queue and feed audio to model without checking scores.
        Flushes internal mel-spectrogram features so residual speech audio
        (e.g. from saying 'cancel') doesn't immediately re-trigger wake word."""
        # First drain whatever is already queued
        while not audio_q.empty():
            try:
                audio_q.get_nowait()
            except Exception:
                break
        # Feed fresh chunks for `seconds` to flush model's internal state
        chunks = int(seconds * _SAMPLE_RATE / _CHUNK_FRAMES)
        for _ in range(chunks):
            if not self._running:
                break
            try:
                chunk = audio_q.get(timeout=0.3)
                ww_model.predict(chunk.flatten())  # feed but ignore score
            except queue.Empty:
                pass
        # Clear scores after cooldown
        for scores in ww_model.prediction_buffer.values():
            scores.clear()

    def _wait_for_wakeword(self, audio_q: queue.Queue, ww_model) -> bool:
        """Consume queue chunks and feed to wake word detector.
        Returns True when detected, False when stopped."""
        while self._running:
            try:
                chunk = audio_q.get(timeout=0.5)
            except queue.Empty:
                continue

            arr = chunk.flatten()
            ww_model.predict(arr)

            for model_name, score in ww_model.prediction_buffer.items():
                if len(score) > 0 and score[-1] >= _WAKEWORD_SCORE_THRESHOLD:
                    logger.info("VoiceThread: wake word '%s' score=%.3f", model_name, score[-1])
                    return True

            # Yield CPU: on a VM, ONNX inference without sleep can starve
            # the audio callback thread sharing the same vCPU pool.
            time.sleep(_WAKEWORD_LOOP_SLEEP)

        return False

    # ── Speech recording with energy VAD ─────────────────────────────────────

    def _record_speech(self, audio_q: queue.Queue) -> "list[np.ndarray] | None":
        """Record from queue until silence. Returns list of int16 chunks or None."""
        frames = []
        silence_chunks = 0
        speech_chunks  = 0
        max_chunks     = int(_MAX_RECORD_SECONDS * _SAMPLE_RATE / _CHUNK_FRAMES)
        silence_limit  = int(_VAD_SILENCE_SECONDS * _SAMPLE_RATE / _CHUNK_FRAMES)

        while self._running and len(frames) < max_chunks:
            try:
                chunk = audio_q.get(timeout=0.5)
            except queue.Empty:
                # No audio coming — treat as silence
                silence_chunks += 1
                if silence_chunks >= silence_limit and speech_chunks >= _VAD_MIN_SPEECH_FRAMES:
                    break
                continue

            arr = chunk.flatten()
            frames.append(arr.copy())

            if _rms(arr) >= _VAD_ENERGY_THRESHOLD:
                speech_chunks += 1
                silence_chunks = 0
            else:
                silence_chunks += 1
                if silence_chunks >= silence_limit and speech_chunks >= _VAD_MIN_SPEECH_FRAMES:
                    break

        if speech_chunks < _VAD_MIN_SPEECH_FRAMES:
            logger.info("VoiceThread: too short, ignoring (%d speech chunks)", speech_chunks)
            return None

        return frames

    # ── STT (faster-whisper) ──────────────────────────────────────────────────

    def _load_stt_model(self):
        from faster_whisper import WhisperModel
        model_size = "tiny"
        device = "cpu"
        logger.info("VoiceThread: loading Whisper model '%s' on %s", model_size, device)
        return WhisperModel(model_size, device=device, compute_type="int8")

    def _transcribe(self, stt_model, frames: list) -> str:
        """Concatenate frames and transcribe directly from numpy array.
        No temp file written — avoids disk I/O overhead on VMs."""
        # Concatenate int16 frames and normalise to float32 [-1, 1]
        audio_int16 = np.concatenate(frames)
        audio_f32   = audio_int16.astype(np.float32) / 32768.0

        # faster-whisper accepts numpy float32 arrays directly
        segments, _ = stt_model.transcribe(
            audio_f32,
            language="en",
            beam_size=1,
            vad_filter=True,           # built-in Silero VAD removes silent segments
            vad_parameters={"min_silence_duration_ms": 300},
        )
        text = " ".join(seg.text for seg in segments).strip()
        logger.info("VoiceThread: transcribed: %r", text)
        return text

    # ── AI command generation ─────────────────────────────────────────────────

    def _transcribe_and_generate(self, stt_model, frames: list) -> str:
        text = self._transcribe(stt_model, frames)
        if not text:
            logger.info("VoiceThread: empty transcription")
            return ""
        logger.info("VoiceThread: generating command for: %r", text)
        return self._generate_command(text)

    def _generate_command(self, user_text: str) -> str:
        """Call psai to generate a shell command from natural language."""
        modules_dir = os.path.join(self.base_dir, "appdata", "terminal_modules")
        if modules_dir not in sys.path:
            sys.path.insert(0, modules_dir)

        try:
            import psai as _ai
        except ImportError as e:
            logger.error("VoiceThread: cannot import psai: %s", e)
            return ""

        config  = _ai._load_config(self.base_dir)
        profile = _ai._active_profile(config)
        if not profile:
            logger.error("VoiceThread: no active API profile")
            return ""

        api_key          = _ai._load_api_key(profile.get("name", ""), self.base_dir)
        provider         = profile.get("provider", "ollama")
        url              = profile.get("url", "") or _ai._DEFAULT_URLS.get(provider, "")
        model            = profile.get("model", "")
        custom_params    = _ai._parse_custom_params(profile)
        disable_thinking = bool(profile.get("disable_thinking", False)) and not custom_params

        sys_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
        prompt = (
            f"System: {sys_info}\n\n"
            "You are an expert Linux/penetration testing assistant. "
            "Convert the following natural language request into a single shell command. "
            "Respond with ONLY the raw command — no explanation, no backticks, no prefix.\n\n"
            f"Request: {user_text}"
        )

        messages = [{"role": "user", "content": prompt}]
        try:
            response = _ai._run_llm(
                provider, model, messages, url, api_key,
                disable_thinking, custom_params,
            )
        except Exception as e:
            logger.error("VoiceThread: AI error: %s", e)
            return ""

        if not response:
            return ""

        return self._clean_command(response)

    @staticmethod
    def _clean_command(text: str) -> str:
        lines_raw = text.strip().splitlines()
        filtered  = []
        in_fence  = False
        in_think  = False
        for raw in lines_raw:
            s  = raw.strip()
            lo = s.lower()
            if s.startswith("```"):
                in_fence = not in_fence
                continue
            if "<think>" in lo or "<thinking>" in lo:
                in_think = True
            if in_think:
                if "</think>" in lo or "</thinking>" in lo:
                    in_think = False
                continue
            if not in_fence and not s:
                continue
            filtered.append(s)

        candidates = []
        for line in filtered:
            if line.lower().startswith(("the ", "here ", "you ", "try ", "this ", "use ", "note", "#")):
                continue
            if line.startswith("`") and line.endswith("`"):
                line = line[1:-1]
            if line:
                candidates.append(line)

        if candidates:
            return candidates[-1]
        for line in reversed(lines_raw):
            if line.strip():
                return line.strip()
        return text.strip()

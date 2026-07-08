import os
import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class PathsMixin:
    def get_notes_path(self):
        # Only resolve the deterministic notes path here — do NOT create the file.
        # An empty file is written lazily on the first real save, and removed again
        # when the note is cleared, so empty scripts never litter scripts_notes/.
        hash_len = 12
        p = Path(self.path).expanduser().resolve()
        base = p.name

        full = str(p)
        h = hashlib.sha1(full.encode("utf-8")).hexdigest()
        script_notes_folder_path = f"{h[:hash_len]}_{base}_notes"
        self.script_note_path = os.path.join(
            self.controller.scripts_notes_folder_path, script_notes_folder_path)

    def _save_notes_to_file(self):
        try:
            current_text = self.notes_field.toPlainText()

            if current_text == self._last_saved_notes:
                return

            self._last_saved_notes = current_text
            self.notes_text = current_text

            # Empty note → don't create the file; remove it if it already exists,
            # so a cleared note leaves no trace on disk.
            if not current_text.strip():
                if os.path.exists(self.script_note_path):
                    try:
                        os.remove(self.script_note_path)
                    except OSError:
                        logger.warning("failed to remove emptied script note", exc_info=True)
                return

            # First real content — make sure the notes folder exists before writing.
            Path(self.controller.scripts_notes_folder_path).mkdir(parents=True, exist_ok=True)
            with open(self.script_note_path, "w", encoding="utf-8") as f:
                f.write(current_text)

        except Exception as e:
            logger.warning("failed to save script notes", exc_info=True)

    @property
    def detail_texts(self):
        return         {
            "help": self.help_text,
            "readme": self.readme_text,
            "notes": self.notes_text,
        }

import os
import hashlib
from pathlib import Path

class PathsMixin:
    def get_notes_path(self):
        hash_len = 12
        p = Path(self.path).expanduser().resolve()
        base = p.name

        full = str(p)
        h = hashlib.sha1(full.encode("utf-8")).hexdigest()
        script_notes_folder_path = f"{h[:hash_len]}_{base}_notes"
        full_note_path = os.path.join(self.controller.scripts_notes_folder_path, script_notes_folder_path)
        exists = os.path.exists(full_note_path)
        if exists:
            self.script_note_path = full_note_path
        else:
            Path(self.controller.scripts_notes_folder_path).mkdir(parents=True, exist_ok=True)
            Path(full_note_path).touch(exist_ok=True)
            self.script_note_path = full_note_path

    def get_history_path(self):
        hash_len = 12
        p = Path(self.path).expanduser().resolve()
        base = p.name

        full = str(p)
        h = hashlib.sha1(full.encode("utf-8")).hexdigest()
        script_history_folder_path = f"{h[:hash_len]}_{base}_history.csv"
        full_history_path = os.path.join(self.controller.scripts_history_folder_path, script_history_folder_path)
        exists = os.path.exists(full_history_path)
        if exists:
            self.script_history_path = full_history_path
        else:
            Path(self.controller.scripts_history_folder_path).mkdir(parents=True, exist_ok=True)
            Path(full_history_path).touch(exist_ok=True)
            self.script_history_path = full_history_path

    def get_favorite_path(self):
        hash_len = 12
        p = Path(self.path).expanduser().resolve()
        base = p.name

        full = str(p)
        h = hashlib.sha1(full.encode("utf-8")).hexdigest()
        script_favorite_folder_path = f"{h[:hash_len]}_{base}_favorite.csv"
        full_favorite_path = os.path.join(self.controller.scripts_favorite_folder_path, script_favorite_folder_path)
        exists = os.path.exists(full_favorite_path)
        if exists:
            self.script_favorite_path = full_favorite_path
        else:
            Path(self.controller.scripts_favorite_folder_path).mkdir(parents=True, exist_ok=True)
            Path(full_favorite_path).touch(exist_ok=True)
            self.script_favorite_path = full_favorite_path

    def get_help_path(self):
        hash_len = 12
        p = Path(self.path).expanduser().resolve()
        base = p.name

        full = str(p)
        h = hashlib.sha1(full.encode("utf-8")).hexdigest()
        script_help_folder_path = f"{h[:hash_len]}_{base}_help.txt"
        full_help_path = os.path.join(self.controller.scripts_help_folder_path, script_help_folder_path)
        exists = os.path.exists(full_help_path)
        if exists:
            self.script_help_path = full_help_path
        else:
            Path(self.controller.scripts_help_folder_path).mkdir(parents=True, exist_ok=True)
            Path(full_help_path).touch(exist_ok=True)
            self.script_help_path = full_help_path

    def get_docs_path(self):
        hash_len = 12
        p = Path(self.path).expanduser().resolve()
        base = p.name

        full = str(p)
        h = hashlib.sha1(full.encode("utf-8")).hexdigest()
        script_docs_folder_path = f"{h[:hash_len]}_{base}_docs.txt"
        full_docs_path = os.path.join(self.controller.scripts_docs_folder_path, script_docs_folder_path)
        exists = os.path.exists(full_docs_path)
        if exists:
            self.script_docs_path = full_docs_path
        else:
            Path(self.controller.scripts_docs_folder_path).mkdir(parents=True, exist_ok=True)
            Path(full_docs_path).touch(exist_ok=True)
            self.script_docs_path = full_docs_path

    def _save_notes_to_file(self):
        try:
            current_text = self.notes_field.toPlainText()

            if current_text == self._last_saved_notes:
                return

            self._last_saved_notes = current_text
            self.notes_text = current_text

            with open(self.script_note_path, "w", encoding="utf-8") as f:
                f.write(current_text)

        except Exception as e:
            pass

    @property
    def detail_texts(self):
        return         {
            "favorite": self.favorite_text,
            "help": self.help_text,
            "docs": self.docs_text,
            "readme": self.readme_text,
            "history": self.history_text,
            "notes": self.notes_text,
        }

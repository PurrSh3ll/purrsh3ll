from PyQt6.QtCore import QThread
from pathlib import Path
import hashlib

class OrphanScriptDataCleaner(QThread):
    def __init__(self, script_data_folders, app_modules_path, user_modules_path, hash_len=12, parent=None):
        super().__init__(parent)
        self.script_data_folders = [Path(p) for p in script_data_folders]
        self.modules_paths = [Path(app_modules_path), Path(user_modules_path)]
        self.hash_len = hash_len

    def run(self):
        valid_prefixes = set()

        for root in self.modules_paths:
            if not root.exists():
                continue

            for py_file in root.rglob("*.py"):
                full = str(py_file.expanduser().resolve())
                h = hashlib.sha1(full.encode("utf-8")).hexdigest()
                prefix = f"{h[:self.hash_len]}_{py_file.name}"
                valid_prefixes.add(prefix)

        for folder in self.script_data_folders:
            if not folder.exists():
                continue

            for file in folder.iterdir():
                if not file.is_file():
                    continue

                if not any(file.name.startswith(prefix) for prefix in valid_prefixes):
                    try:
                        file.unlink()
                    except Exception as e:
                        pass

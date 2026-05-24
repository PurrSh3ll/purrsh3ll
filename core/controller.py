import logging

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

logger = logging.getLogger(__name__)

from core.theme_manager import change_theme
from gui.widgets.observable_panel import ObserverPanel
from gui.watchers.watchdogs_python_files import WatchdogThread
from gui.watchers.py_scripts_cleaner import OrphanScriptDataCleaner

from core.mixins.panel_manager import PanelManagerMixin
from core.mixins.module_tree import ModuleTreeMixin
from core.mixins.tab_manager import TabManagerMixin
from core.mixins.terminal_manager import TerminalManagerMixin
from core.file_types import FILES_CATEGORY

import os
import sys
import json
import pkgutil
import hashlib
import subprocess
import threading
from pathlib import Path

class Controller(PanelManagerMixin, ModuleTreeMixin, TabManagerMixin, TerminalManagerMixin):
    widgets = {}
    panel_widgets = {}
    expanded_modules = []
    actual_theme = {}
    themes = []
    _icon_cache = {}
    dynamic_vars = {}
    purr_allowed_names = ["psnmap", "psc2"]
    purr_term_numb = 0
    data = {}
    text_chunks = {}
    opened_tabs_tree = {}
    tabs_stylesheet = ""
    messagebox_stylesheet = ""
    command_palette_stylesheet = ""
    tab_number = 0
    qss_QPainter = {}
    text_loaders = []
    text_highlighters = []
    change_theme_limit_tabs = 30
    open_loaders = {}
    threads = []
    terminal_idx = 0
    terminals = {}
    terminals_stylesheet = ""
    terminal_qss_scroll = ""
    qss_QInputDialog_terminal = ""
    terminal_buffer = ""
    qss_info = ""

    files_category = FILES_CATEGORY

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(Controller, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, '_inicialized'):
            self._inicialized = True
            self.base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            self.config_path = os.path.join(self.base_path, "appdata", "app_config.json")
            self.venv_script = os.path.join(self.base_path, "appdata", "venv_list.sh")
            self.start_x, self.start_y = 100, 100
            self.width, self.height = 800, 600
            self.lightweight_web_browser = True
            self.web_browser_3d_info = True
            self.game_3d_info = True
            self.save_system_vars = True
            self.delete_logs_at_close = True
            self.delete_notes_at_close = False
            self.terminal_history_max_entries = 5000
            self.terminal_history_disabled = False

            get_venv_thread = threading.Thread(target=self.generate_venv_list_json, daemon=True)
            get_venv_thread.start()

            if os.path.exists(self.config_path):
                try:
                    with open(self.config_path, "r", encoding="utf-8") as f:
                        config = json.load(f)

                    win_cfg = config.get("window", {})
                    performance = config.get("performance", {})
                    behavior = config.get("behavior", {})

                    self.width, self.height = win_cfg.get("resolution", [self.width, self.height])
                    self.start_x, self.start_y = win_cfg.get("start_screen", [self.start_x, self.start_y])
                    self.lightweight_web_browser = performance.get("lightweight_web_browser", True)
                    self.save_system_vars = behavior.get("save_sys_vars_at_close", True)
                    self.delete_logs_at_close = behavior.get("delete_logs_at_close", True)
                    self.delete_notes_at_close = behavior.get("delete_notes_at_close", False)
                    self.session_restore_enabled = behavior.get("restore_session_at_start", True)
                    self.terminal_history_max_entries = behavior.get("terminal_history_max_entries", 5000)
                    self.terminal_history_disabled = behavior.get("terminal_history_disabled", False)

                except Exception as e:
                    logger.warning("Failed to load config from %s", self.config_path, exc_info=True)
            else:
                pass

            if not hasattr(self, 'session_restore_enabled'):
                self.session_restore_enabled = True

            self.slide_panel_visible = False
            self.mode_panel_visible = False
            self.chat_panel_visible = False
            self.notes_panel_visible = False
            self.snippet_panel_visible = False
            self.console_args = {}
            self.side_buttons = ["slide_button", "mode_button", "chat_button", "notes_button", "snippet_button"]

            self.dynamic_vars_path = os.path.join(self.base_path, 'appdata', 'dynamic_variables.json')
            self.interpreters_json = os.path.join(self.base_path, 'appdata', 'venv_list.json')
            self.imports_map_json = os.path.join(self.base_path, 'appdata', 'imports_map.json')
            self.scripts_notes_folder_path = os.path.join(self.base_path, 'appdata', 'scripts_notes')
            self.scripts_history_folder_path = os.path.join(self.base_path, 'appdata', 'scripts_history')
            self.scripts_favorite_folder_path = os.path.join(self.base_path, 'appdata', 'scripts_favorities')
            self.scripts_help_folder_path = os.path.join(self.base_path, 'appdata', 'scripts_help')
            self.scripts_docs_folder_path = os.path.join(self.base_path, 'appdata', 'scripts_docs')
            self.user_guide_path = os.path.join(self.base_path, 'appdata', 'user_guide.md')
            self.manual_path = os.path.join(self.base_path, 'appdata', 'manual.md')
            self.home_dir = os.path.expanduser("~")
            self.app_modules_path = os.path.join(self.base_path, "appmodules")
            self.user_modules_path = os.path.join(self.base_path, "usermodules")
            self.icons_path = os.path.join(self.base_path, "icons")
            self.sys_vars_path = os.path.join(self.base_path, "appdata", "terminal_modules", "system_vars.zsh")
            self.observer_panel_state_path = os.path.join(self.base_path, "appdata", "ob_panel_state.json")
            self.session_path = os.path.join(self.base_path, "appdata", "session.json")
            self.build_in_libs = self.get_std_lib()
            self.themes_path = os.path.join(self.base_path, 'appdata', 'themes.json')
            self._debounce_ms = 500
            self._pending_update_message = None
            self._update_timer = QTimer()
            self._update_timer.setSingleShot(True)
            self._update_timer.timeout.connect(self._do_update_modules)

            self.SCRIPT_DATA_FOLDERS = [
                f"{self.base_path}/appdata/scripts_docs",
                f"{self.base_path}/appdata/scripts_help",
                f"{self.base_path}/appdata/scripts_favorities",
                f"{self.base_path}/appdata/scripts_history",
                f"{self.base_path}/appdata/scripts_notes",
            ]

            self.watchdog = WatchdogThread([
                self.app_modules_path,
                self.user_modules_path,
            ])
            self.watchdog.file_deleted.connect(self.cleanup_script_data)
            self.watchdog.start()

            self.orphan_cleaner = OrphanScriptDataCleaner(
                self.SCRIPT_DATA_FOLDERS,
                self.app_modules_path,
                self.user_modules_path,
            )
            self.orphan_cleaner.start()

            self._rag_watcher: object = None
            self._rag_index_worker: object = None

    # ── RAG auto-index ────────────────────────────────────────────────────────
    def _get_rag_kb_path(self) -> str:
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            rag = cfg.get("rag", {})
            if rag.get("knowledge_base", "braindump") == "braindump":
                return os.path.join(self.base_path, "appmodules", "BrainDump")
            return rag.get("custom_path", "")
        except Exception:
            return ""

    def _get_rag_model(self) -> str:
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            return cfg.get("rag", {}).get(
                "embedding_model",
                "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
            )
        except Exception:
            return "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"

    def start_rag_watcher(self):
        self.stop_rag_watcher()
        kb_path = self._get_rag_kb_path()
        if not kb_path:
            return
        try:
            os.makedirs(kb_path, exist_ok=True)
        except OSError:
            return
        from core.rag.rag_watcher import RagWatcher
        self._rag_watcher = RagWatcher(kb_path)
        self._rag_watcher.changes_detected.connect(self._on_rag_changes_detected)
        self._rag_watcher.start()

    def stop_rag_watcher(self):
        if self._rag_watcher is not None:
            self._rag_watcher.stop()
            self._rag_watcher.wait(3000)
            self._rag_watcher = None

    def _on_rag_changes_detected(self):
        if self._rag_index_worker is not None:
            return  # already indexing — skip, next change will re-trigger
        kb_path = self._get_rag_kb_path()
        if not kb_path or not os.path.isdir(kb_path):
            return
        model_name = self._get_rag_model()
        from core.rag.index_worker import IndexWorker
        worker = IndexWorker(kb_path, self.base_path, model_name)
        self._rag_index_worker = worker

        def _done(_result):
            self._rag_index_worker = None

        worker.finished.connect(_done)
        worker.start()

    def register_widget(self, name: str, widget):
        Controller.widgets[name] = widget

    def get_widget(self, name: str):
        return Controller.widgets.get(name)

    def load_themes(self):
        try:
            with open(self.themes_path, 'r') as f:
                data = json.load(f)
                current = data.get('current_theme', 'default')
                themes = data.get('themes', {})
                Controller.actual_theme = themes.get(current, {})
                Controller.themes = list(themes.keys())
        except (FileNotFoundError, json.JSONDecodeError):
            Controller.actual_theme = {}
            Controller.themes = []

    def change_actual_theme(self, theme):
        if theme is None:
            change_theme(self)
            return
        if len(Controller.opened_tabs_tree) > Controller.change_theme_limit_tabs:
            Controller.widgets["theme_limit_dialog"].show()
            return
        else:
            Controller.widgets["theme_dial_info"].show()
            QApplication.processEvents()

        try:
            with open(self.themes_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return
        except json.JSONDecodeError as e:
            return

        if "themes" in data and theme in data["themes"]:
            if data.get("current_theme") == theme:
                Controller.widgets["theme_dial_info"].close()
                return
            data["current_theme"] = theme
        else:
            return

        with open(self.themes_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        Controller.actual_theme = data["themes"][theme]

        change_theme(self)
        dial = Controller.widgets["theme_dial_info"]
        QTimer.singleShot(0, dial.close)

    def load_dynamic_variables(self):
        self.dynamic_vars.clear()

        try:
            with open(self.dynamic_vars_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for name, value in data.items():
                self.dynamic_vars[name] = value

        except FileNotFoundError:
            pass
        except json.JSONDecodeError:
            pass

    def load_sys_vars(self):
        if not os.path.exists(self.observer_panel_state_path):
            return

        if os.path.getsize(self.observer_panel_state_path) == 0:
            return

        try:
            with open(self.observer_panel_state_path, "r", encoding="utf-8") as f:
                state = json.load(f)
        except json.JSONDecodeError:
            return
        except Exception as e:
            return

        rows = state.get("rows", [])
        observer = self.widgets["op_rows_panel"]

        for row_data in reversed(rows):
            observer.create_row()

            row_id = observer.row_counter

            name_edit = self.panel_widgets.get(f"observer_row_{row_id}_name_edit")
            dynamic_name_combo = self.panel_widgets.get(f"observer_row_{row_id}_dynamic_name_combo")
            value_edit = self.panel_widgets.get(f"observer_row_{row_id}_value_edit")
            type_combo = self.panel_widgets.get(f"observer_row_{row_id}_type_combo")

            if not (value_edit and type_combo):
                continue

            row_type = row_data.get("type", "static")
            row_name = row_data.get("name", "")
            row_value = row_data.get("value", "")

            type_combo.setCurrentText(row_type)

            if row_type == "dynamic" and dynamic_name_combo:
                index = dynamic_name_combo.findText(row_name)
                if index >= 0:
                    dynamic_name_combo.setCurrentIndex(index)
                else:
                    dynamic_name_combo.setCurrentText(row_name)
            else:
                if name_edit:
                    name_edit.setText(row_name)

            value_edit.setText(row_value)

        try:
            if os.path.exists(self.sys_vars_path):
                with open(self.sys_vars_path, "w", encoding="utf-8") as f:
                    pass
        except Exception as e:
            pass

    def cleanup_script_data(self, path: str, hash_len: int = 12):
        p = Path(path).expanduser().resolve()
        base = p.name

        full = str(p)
        h = hashlib.sha1(full.encode("utf-8")).hexdigest()
        prefix = f"{h[:hash_len]}_{base}"

        for folder in self.SCRIPT_DATA_FOLDERS:
            dir_path = Path(folder)
            if not dir_path.exists():
                continue

            for file in dir_path.iterdir():
                if file.is_file() and file.name.startswith(prefix):
                    try:
                        file.unlink()
                    except Exception as e:
                        pass

    def get_std_lib(self):
        stdlib_dir = os.path.dirname(os.__file__)
        file_modules = {m.name for m in pkgutil.iter_modules([stdlib_dir])}
        builtin_modules = set(sys.builtin_module_names)
        return file_modules | builtin_modules

    def generate_venv_list_json(self):

        base_path = Path(self.base_path)
        appdata = base_path / "appdata"
        appdata.mkdir(exist_ok=True)
        output_path = appdata / "venv_list.json"

        SYS_PATH = "/usr/bin:/usr/local/bin:/bin:/sbin"
        GLOBAL_PY = None

        for p in SYS_PATH.split(":"):
            candidate = Path(p) / "python3"
            if candidate.exists() and os.access(candidate, os.X_OK):
                GLOBAL_PY = str(candidate)
                break

        if not GLOBAL_PY:
            if Path("/usr/bin/python3").exists():
                GLOBAL_PY = "/usr/bin/python3"
            else:
                GLOBAL_PY = "unknown"

        GLOBAL_PKGS_JSON = []
        if GLOBAL_PY != "unknown":
            try:
                out = subprocess.check_output(
                    [GLOBAL_PY, "-m", "pip", "list", "--format=json"],
                    stderr=subprocess.DEVNULL
                )
                GLOBAL_PKGS_JSON = json.loads(out.decode("utf-8"))
            except Exception:
                logger.warning("Failed to list global Python packages for %s", GLOBAL_PY, exc_info=True)
                GLOBAL_PKGS_JSON = []

        result = [{"path": GLOBAL_PY, "packages": GLOBAL_PKGS_JSON}]

        home = Path.home()
        for cfg in home.rglob("pyvenv.cfg"):
            venv_dir = cfg.parent
            venv_python = venv_dir / "bin" / "python"

            pkgs = []
            if venv_python.exists():
                try:
                    out = subprocess.check_output(
                        [str(venv_python), "-m", "pip", "list", "--format=json"],
                        stderr=subprocess.DEVNULL
                    )
                    pkgs = json.loads(out.decode("utf-8"))
                except Exception:
                    logger.warning("Failed to list packages for venv %s", venv_python, exc_info=True)
                    pkgs = []

            result.append({"path": str(venv_python), "packages": pkgs})

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

    def apply_agent_files(self, agent_role: str, skills_set: str):
        import shutil
        logs_dir = os.path.join(self.base_path, "appdata", "logs")
        os.makedirs(logs_dir, exist_ok=True)

        dst_claude = os.path.join(logs_dir, "CLAUDE.md")
        if os.path.exists(dst_claude):
            try:
                os.remove(dst_claude)
            except Exception as ex:
                pass
        if agent_role and agent_role != "none":
            src_claude = os.path.join(
                self.base_path, "appdata", "agent_modes", "agent_md", agent_role, "CLAUDE.md"
            )
            if os.path.isfile(src_claude):
                try:
                    shutil.copy2(src_claude, dst_claude)
                except Exception as ex:
                    logger.warning("Failed to copy agent CLAUDE.md from %s", src_claude, exc_info=True)

        dst_skills_root = os.path.join(logs_dir, ".claude", "skills")
        if os.path.isdir(dst_skills_root):
            try:
                shutil.rmtree(dst_skills_root)
            except Exception as ex:
                pass
        if skills_set and skills_set != "none":
            src_skills_root = os.path.join(
                self.base_path, "appdata", "agent_modes", "skills", skills_set
            )
            if os.path.isdir(src_skills_root):
                os.makedirs(dst_skills_root, exist_ok=True)
                for skill_name in os.listdir(src_skills_root):
                    if skill_name.startswith("."):
                        continue
                    src_skill = os.path.join(src_skills_root, skill_name)
                    if not os.path.isdir(src_skill):
                        continue
                    try:
                        shutil.copytree(src_skill, os.path.join(dst_skills_root, skill_name))
                    except Exception as ex:
                        logger.warning("Failed to copy skill '%s'", skill_name, exc_info=True)

    def open_command_palette(self):
        if not hasattr(self, '_command_palette') or self._command_palette is None:
            from gui.dialogs.command_palette import CommandPalette
            self._command_palette = CommandPalette(self, parent=self.get_widget("main_window"))
        palette = self._command_palette
        palette.setStyleSheet(self.__class__.command_palette_stylesheet)
        palette.open_palette()

    def open_settings(self):
        Controller.widgets["settings_dialog"].exec()

    def open_ai_settings(self):
        self._refresh_settings_agent_combos()
        Controller.widgets["ai_settings_dialog"].exec()

    def _refresh_settings_agent_combos(self):
        import json, os
        try:
            cfg = {}
            if os.path.exists(self.config_path):
                with open(self.config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f).get("llama", {})
        except Exception:
            return

        base = os.path.join(self.base_path, "appdata", "agent_modes")

        role_combo = Controller.widgets.get("ai_settings_agent_role_combo")
        if role_combo:
            roles_dir = os.path.join(base, "agent_md")
            roles = sorted(os.listdir(roles_dir)) if os.path.isdir(roles_dir) else []
            role_combo.blockSignals(True)
            role_combo.clear()
            role_combo.addItem("none")
            role_combo.addItems(roles)
            saved = cfg.get("agent_role", "")
            if saved and role_combo.findText(saved) != -1:
                role_combo.setCurrentText(saved)
            role_combo.blockSignals(False)

        skills_combo = Controller.widgets.get("ai_settings_skills_combo")
        if skills_combo:
            skills_dir = os.path.join(base, "skills")
            skills = sorted(os.listdir(skills_dir)) if os.path.isdir(skills_dir) else []
            skills_combo.blockSignals(True)
            skills_combo.clear()
            skills_combo.addItem("none")
            skills_combo.addItems(skills)
            saved = cfg.get("skills_set", "")
            if saved and skills_combo.findText(saved) != -1:
                skills_combo.setCurrentText(saved)
            skills_combo.blockSignals(False)

    def open_qterm_help(self):
        Controller.widgets["qterminal_dialog"].exec()

    def open_qt_help(self):
        Controller.widgets["qt_dialog"].exec()

    def open_licenses_help(self):
        Controller.widgets["licenses_dialog"].exec()

    def open_author_dialog(self):
        Controller.widgets["author_dialog"].exec()

controller_instance = Controller()

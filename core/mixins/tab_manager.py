import json
import logging
import os
from PyQt6.QtCore import Qt

logger = logging.getLogger(__name__)
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QApplication, QStyle, QTextEdit

from file_loaders.text_file import Text_file
from file_loaders.json_file import Json_file
from file_loaders.xml_file import Xml_file
from file_loaders.md_file import Markdown_file
from file_loaders.powershell_file import Powershell_file
from file_loaders.winshell_file import Win_file
from file_loaders.sh_file import Sh_file
from file_loaders.ansi_c_file import Ansi_c_file
from file_loaders.asm_file import Asm_file
from file_loaders.cpp_file import Cpp_file
from file_loaders.csharp_file import Csharp_file
from file_loaders.csv_file import Csv_file
from file_loaders.game_file import Game_file
from file_loaders.go_file import Go_file
from file_loaders.html_file import Html_file
from file_loaders.java_file import Java_file
from file_loaders.javascript_file import Javascript_file
from file_loaders.htaccess_file import Htaccess_file
from file_loaders.lua_file import Lua_file
from file_loaders.noextension_file import Noextension_file
from file_loaders.php_file import Php_file
from file_loaders.python_file import Python_file
from file_loaders.purr_script import Purr_script
from file_loaders.perl_file import Perl_file
from file_loaders.ruby_file import Ruby_file
from file_loaders.sql_file import Sql_file
from file_loaders.psnmap_file import Purr_file
from file_loaders.psc2_file import Psc2_file
from file_loaders.unsupported_file import Unsupported_file
from file_loaders.visualbasic_file import Visualbasic_file

FILE_LOADERS = {
    "Text_file": Text_file,
    "Json_file": Json_file,
    "Xml_file": Xml_file,
    "Markdown_file": Markdown_file,
    "Powershell_file": Powershell_file,
    "Win_file": Win_file,
    "Sh_file": Sh_file,
    "Ansi_c_file": Ansi_c_file,
    "Asm_file": Asm_file,
    "Cpp_file": Cpp_file,
    "Csharp_file": Csharp_file,
    "Csv_file": Csv_file,
    "Game_file": Game_file,
    "Go_file": Go_file,
    "Html_file": Html_file,
    "Java_file": Java_file,
    "Javascript_file": Javascript_file,
    "Htaccess_file": Htaccess_file,
    "Lua_file": Lua_file,
    "Noextension_file": Noextension_file,
    "Php_file": Php_file,
    "Python_file": Python_file,
    "Purr_script": Purr_script,
    "Perl_file": Perl_file,
    "Ruby_file": Ruby_file,
    "Sql_file": Sql_file,
    "Purr_file": Purr_file,
    "Psc2_file": Psc2_file,
    "Unsupported_file": Unsupported_file,
    "Visualbasic_file": Visualbasic_file,
}

class TabManagerMixin:

    def _load_file_into_tab(self, full_path: str, icon_token: str, file_class_name: str, tab_entry: dict):
        execution_tabs = self.widgets['execution_tabs']

        tab_name = os.path.basename(full_path)
        folder_name = os.path.basename(os.path.dirname(full_path))
        existing_tab_names = {execution_tabs.tabText(i) for i in range(execution_tabs.count())}
        if tab_name in existing_tab_names:
            tab_name = f"{folder_name}/{tab_name}"

        style = QApplication.style()
        default_icon = style.standardIcon(QStyle.StandardPixmap.SP_FileIcon)

        if icon_token and icon_token != "builtin-default":
            icon = self.get_icon(icon_name=icon_token, default=default_icon)
            if icon is None:
                icon = default_icon
        else:
            icon = default_icon

        try:
            file_class = FILE_LOADERS[file_class_name]
            loader = file_class()
            content_widget = loader.load_file(
                full_path,
                parent=self,
                target_widget=None,
                threads_list=self.threads
            )
            try:
                content_widget._loader = loader
            except Exception:
                pass
        except Exception as e:
            logger.error("Failed to load file into tab: %s", full_path, exc_info=True)
            content_widget = QTextEdit(parent=execution_tabs)
            content_widget.setReadOnly(True)
            content_widget.setText(f"❌ Error loading file:\n{e}")

        try:
            content_widget.setStyleSheet(self.tabs_stylesheet)
        except Exception:
            pass

        type(self).tab_number += 1
        self.widgets[f"tab_container_{self.tab_number}"] = content_widget

        execution_tabs.addTab(content_widget, icon, tab_name)
        execution_tabs.add_tool_tip(full_path)
        execution_tabs.setCurrentWidget(content_widget)

        tab_entry["editor"] = content_widget
        self.opened_tabs_tree[full_path] = tab_entry

        if len(self.opened_tabs_tree) > 0:
            self.widgets["welcome_tab_text"].setVisible(False)

    def open_new_tab_for_tree(self, item, column: int = 0):
        if item is None:
            return
        if item.data(0, Qt.ItemDataRole.UserRole) == "__separator__":
            return
        execution_tabs = self.widgets['execution_tabs']
        full_path = item.data(0, Qt.ItemDataRole.UserRole)
        icon_token = item.data(0, Qt.ItemDataRole.UserRole + 1)
        file_class_name = item.data(0, Qt.ItemDataRole.UserRole + 3)

        if os.path.isdir(full_path):
            return

        if full_path in self.opened_tabs_tree:
            tab = self.opened_tabs_tree[full_path]["editor"]
            execution_tabs.setCurrentIndex(execution_tabs.indexOf(tab))
            return

        self._load_file_into_tab(full_path, icon_token, file_class_name, {"item": item})

    def open_new_tab_for_terminal(self, file, mode="Default", column: int = 0):
        extension = os.path.splitext(file)[1][1:].lower() or "noextension"

        if mode == "Default":
            if extension == "noextension":
                icon_token = "__noextension_file.png"
                file_class_name = "Noextension_file"
            else:
                token = self.files_category.get(extension, "__unsupported_file")
                icon_token = None
                if extension == "py":
                    icon_token = "__python_file.png"
                elif extension == "purr":
                    stem = os.path.splitext(os.path.basename(file))[0].lower()
                    if stem == "psc2":
                        token = "__psc2_file"
                        icon_token = "__purr_file.png"
                    elif stem != "psnmap":
                        token = "__unsupported_file"
                if icon_token is None:
                    icon_token = token if token.endswith(".png") else f"{token}.png"
                file_class_name = token[2:].capitalize() if token.startswith("__") else token.capitalize()
        else:
            token = self.files_category.get(extension, "__unsupported_file")
            icon_token = token if token.endswith(".png") else f"{token}.png"
            file_class_name = self.files_category.get(mode, "__unsupported_file")
            file_class_name = file_class_name[2:].capitalize() if file_class_name.startswith(
                "__") else file_class_name.capitalize()

        execution_tabs = self.widgets['execution_tabs']
        if file in self.opened_tabs_tree:
            tab = self.opened_tabs_tree[file]["editor"]
            execution_tabs.setCurrentIndex(execution_tabs.indexOf(tab))
            return

        self._load_file_into_tab(
            file, icon_token, file_class_name,
            {"item": None, "source": "terminal", "icon_token": icon_token, "file_class_name": file_class_name}
        )

    def update_dropdown_menu(self):
        self.widgets["dropdown_menu"].clear()
        for i in range(self.widgets["execution_tabs"].count()):
            action = QAction(self.widgets["execution_tabs"].tabText(i), self.widgets["main_window"])
            action.triggered.connect(lambda checked=False, idx=i: self.widgets["execution_tabs"].setCurrentIndex(idx))
            self.widgets["dropdown_menu"].addAction(action)

    def save_session(self):
        if not getattr(self, 'session_restore_enabled', True):
            try:
                if os.path.exists(self.session_path):
                    os.remove(self.session_path)
            except Exception:
                pass
            return

        execution_tabs = self.widgets.get('execution_tabs')
        if execution_tabs is None:
            return

        paths = []
        for i in range(execution_tabs.count()):
            tip = execution_tabs.tabToolTip(i)
            if tip and os.path.isfile(tip):
                paths.append(tip)

        data = {
            "active_index": execution_tabs.currentIndex(),
            "tabs": paths,
        }

        try:
            with open(self.session_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            logger.warning("Failed to save session to %s", self.session_path, exc_info=True)

    def restore_session(self):
        if not getattr(self, 'session_restore_enabled', True):
            return

        if not os.path.exists(self.session_path):
            return

        try:
            with open(self.session_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            logger.warning("Failed to read session file %s", self.session_path, exc_info=True)
            return

        tabs = data.get("tabs", [])
        active_index = data.get("active_index", 0)

        for path in tabs:
            if os.path.isfile(path):
                try:
                    self.open_new_tab_for_terminal(file=path)
                except Exception:
                    logger.warning("Failed to restore tab: %s", path, exc_info=True)

        execution_tabs = self.widgets.get('execution_tabs')
        if execution_tabs and 0 <= active_index < execution_tabs.count():
            execution_tabs.setCurrentIndex(active_index)

    def update_dropdown_menu_terminals(self):
        if self.widgets.get("terminal_tabs") is None:
            return
        self.widgets["dropdown_terminal_menu"].clear()
        for i in range(self.widgets["terminal_tabs"].count()):
            action = QAction(self.widgets["terminal_tabs"].tabText(i), self.widgets["main_window"])
            action.triggered.connect(lambda checked=False, idx=i: self.widgets["terminal_tabs"].setCurrentIndex(idx))
            self.widgets["dropdown_terminal_menu"].addAction(action)

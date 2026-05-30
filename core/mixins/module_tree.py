import os
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QFont
from PyQt6.QtWidgets import QApplication, QStyle, QTreeWidgetItem

# Extensions that are well-known formats the app cannot open meaningfully.
# Everything NOT in this set and NOT in FILES_CATEGORY gets a neutral icon
# (__noextension_file) because the app may still open it (e.g. via Pygments).
_KNOWN_UNSUPPORTED = {
    # Video
    "rmvb", "vob",
    # Audio
    "m4a", "mid", "midi", "ra", "amr",
    # Archives
    "gz", "bz2", "xz", "rar", "lzma", "zst", "tgz",
    "cab", "deb", "rpm", "pkg", "dmg", "iso",
    # Presentations / proprietary documents
    "ppt", "pptx", "odp", "key", "pages", "numbers",
    # Fonts
    "ttf", "otf", "woff", "woff2", "eot",
    # Executables / system binaries
    "exe", "msi", "dll", "so", "dylib", "bin", "sys", "apk", "ipa",
    # Compiled bytecode / JVM
    "pyc", "pyo", "class", "jar", "war", "ear",
    # Object files / static libraries
    "o", "a", "obj", "lib",
    # Database internals
    "mdb", "accdb", "frm", "ibd", "myd",
    # Raw / proprietary images and design files
    "raw", "cr2", "cr3", "nef", "nrw", "arw", "dng",
    "heic", "heif", "avif", "psd", "ai", "eps",
    # 3D models / game assets
    "fbx", "blend", "stl", "dae", "3ds", "pak", "wad", "bsp",
    # Binary certificates
    "p12", "pfx", "der", "cer",
}

class ModuleTreeMixin:

    def filter_tree(self, text):
        def filter_item(item, text):
            match = text.lower() in item.text(0).lower()
            any_child_visible = False

            for i in range(item.childCount()):
                child = item.child(i)
                child_visible = filter_item(child, text)
                any_child_visible = any_child_visible or child_visible

            item.setHidden(not (match or any_child_visible))
            return match or any_child_visible

        for i in range(self.get_widget("tree").topLevelItemCount()):
            item = self.get_widget("tree").topLevelItem(i)
            filter_item(item, text)

    def get_icon(self, icon_name: str, default: QIcon) -> QIcon:
        key = os.path.basename(icon_name) if icon_name else ""

        if key in self._icon_cache:
            return self._icon_cache[key]

        path = os.path.join(self.icons_path, key)
        if os.path.exists(path):
            icon = QIcon(path)
        else:
            icon = default

        self._icon_cache[key] = icon
        return icon

    def update_modules(self, message=None):
        tree = self.widgets["tree"]
        selected = tree.currentItem()
        selected_path = selected.data(0, Qt.ItemDataRole.UserRole) if selected else None
        tree.clear()
        font = QFont()
        font.setPointSize(12)
        tree.setFont(font)
        def get_ordered_entries(path):
            entries = os.listdir(path)
            return sorted(entries, key=lambda x: (x.lower(), x))

        style = QApplication.style()
        default_dir_icon = style.standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        default_file_icon = style.standardIcon(QStyle.StandardPixmap.SP_FileIcon)

        def set_folder_image(item: QTreeWidgetItem):
            entry_path = item.data(0, Qt.ItemDataRole.UserRole)
            parts = os.path.normpath(entry_path).split(os.sep)
            if len(parts) >= 2:
                icon_name = f"__{parts[-2]}_{parts[-1]}.png"
                if not os.path.exists(os.path.join(self.icons_path, icon_name)):
                    icon_name = f"__{parts[-1]}.png"
            else:
                icon_name = f"__{parts[-1]}.png"
            item.setIcon(0, self.get_icon(icon_name, default_dir_icon))
            item.setData(0, Qt.ItemDataRole.UserRole + 1, icon_name)

        def set_file_image(item: QTreeWidgetItem):
            file_path = item.data(0, Qt.ItemDataRole.UserRole)
            category = "__unsupported_file"

            if not file_path:
                item.setData(0, Qt.ItemDataRole.UserRole + 2, category)
                item.setData(0, Qt.ItemDataRole.UserRole + 3, category.lstrip("_").capitalize())
                item.setIcon(0, self.get_icon(f"{category}.png", default_file_icon))
                item.setData(0, Qt.ItemDataRole.UserRole + 1, f"{category}.png")
                return

            file_path = os.path.abspath(file_path)
            basename = os.path.basename(file_path)
            ext = os.path.splitext(basename)[1].lower().lstrip(".")

            if not ext and basename.startswith("."):
                dotname = basename[1:]
                if dotname and "." not in dotname:
                    ext = dotname.lower()

            icon_category = None
            if ext:
                if ext in self.files_category:
                    category = self.files_category[ext]
                elif ext in _KNOWN_UNSUPPORTED:
                    category = "__unsupported_file"
                else:
                    category = "__noextension_file"
                if ext == "purr":
                    stem = os.path.splitext(basename)[0].lower()
                    if stem == "psc2":
                        category = "__psc2_file"
                        icon_category = "__purr_file"
                    elif stem != "psnmap":
                        category = "__unsupported_file"
                elif ext == "py":
                    icon_category = "__python_file"
            else:
                category = "__noextension_file"

            item.setData(0, Qt.ItemDataRole.UserRole + 2, category)
            class_name = category.lstrip("_").capitalize()
            item.setData(0, Qt.ItemDataRole.UserRole + 3, class_name)

            icon_filename = f"{icon_category if icon_category else category}.png"
            item.setIcon(0, self.get_icon(icon_filename, default_file_icon))
            item.setData(0, Qt.ItemDataRole.UserRole + 1, icon_filename)

        def add_items_recursively(parent_item, current_path):
            for item_name in sorted(os.listdir(current_path), key=lambda x: (x.lower(), x)):
                full_path = os.path.join(current_path, item_name)
                item = QTreeWidgetItem()
                item.setText(0, item_name)
                item.setData(0, Qt.ItemDataRole.UserRole, full_path)

                if os.path.isdir(full_path):
                    set_folder_image(item)
                    parent_item.addChild(item)
                    add_items_recursively(item, full_path)
                else:
                    set_file_image(item)
                    parent_item.addChild(item)

        for entry_name in get_ordered_entries(self.app_modules_path):
            entry_path = os.path.join(self.app_modules_path, entry_name)
            item = QTreeWidgetItem()
            item.setText(0, entry_name)
            item.setData(0, Qt.ItemDataRole.UserRole, entry_path)

            if os.path.isdir(entry_path):
                set_folder_image(item)
                tree.addTopLevelItem(item)
                add_items_recursively(item, entry_path)
            else:
                set_file_image(item)
                tree.addTopLevelItem(item)

        separator_item = QTreeWidgetItem()
        separator_item.setText(0, "─────────")
        separator_font = QFont()
        separator_font.setBold(True)
        separator_item.setFont(0, separator_font)
        separator_item.setFlags(Qt.ItemFlag.NoItemFlags)
        separator_item.setData(0, Qt.ItemDataRole.UserRole, "__separator__")
        tree.addTopLevelItem(separator_item)

        for entry_name in sorted(os.listdir(self.user_modules_path), key=lambda x: (x.lower(), x)):
            entry_path = os.path.join(self.user_modules_path, entry_name)
            item = QTreeWidgetItem()
            item.setText(0, entry_name)
            item.setData(0, Qt.ItemDataRole.UserRole, entry_path)

            if os.path.isdir(entry_path):
                set_folder_image(item)
                tree.addTopLevelItem(item)
                add_items_recursively(item, entry_path)
            else:
                set_file_image(item)
                tree.addTopLevelItem(item)

        def expand_items_recursively(item):
            full_path = item.data(0, Qt.ItemDataRole.UserRole)
            if full_path in self.expanded_modules:
                item.setExpanded(True)
            for i in range(item.childCount()):
                expand_items_recursively(item.child(i))

        for i in range(tree.topLevelItemCount()):
            expand_items_recursively(tree.topLevelItem(i))

        if selected_path and selected_path != "__separator__":
            def restore_selection(item):
                if item.data(0, Qt.ItemDataRole.UserRole) == selected_path:
                    tree.setCurrentItem(item)
                    return True
                for i in range(item.childCount()):
                    if restore_selection(item.child(i)):
                        return True
                return False
            for i in range(tree.topLevelItemCount()):
                if restore_selection(tree.topLevelItem(i)):
                    break

    def schedule_update_modules(self, message=None):
        if message:
            parts = message.split(" ", 1)
            action = parts[0]
            path = parts[1] if len(parts) > 1 else ""
            if action == "modified":
                return
            if path and not (
                path.startswith(self.app_modules_path) or
                path.startswith(self.user_modules_path)
            ):
                return
        self._pending_update_message = message
        self._update_timer.start(self._debounce_ms)

    def _do_update_modules(self):
        try:
            self.update_modules(self._pending_update_message)
        finally:
            self._pending_update_message = None

    def on_item_expand(self, item: QTreeWidgetItem):
        full_path = item.data(0, Qt.ItemDataRole.UserRole)
        if item.isExpanded():
            if full_path not in self.expanded_modules:
                self.expanded_modules.append(full_path)
        else:
            if full_path in self.expanded_modules:
                self.expanded_modules.remove(full_path)

    def update_dropdown_visibility(self):
        tab_bar = self.widgets["execution_tabs"]
        total_tabs_width = sum(tab_bar.tabBar().tabRect(i).width() for i in range(tab_bar.count()))
        if total_tabs_width > tab_bar.width():
            self.widgets["dropdown_button"].show()
        else:
            self.widgets["dropdown_button"].hide()

    def update_dropdown_terminals(self):
        tab_bar = self.widgets.get("terminal_tabs")
        if tab_bar is None:
            return
        tab_bar = self.widgets["terminal_tabs"]
        total_tabs_width = sum(tab_bar.tabBar().tabRect(i).width() for i in range(tab_bar.count()))
        if total_tabs_width > tab_bar.width():
            self.widgets["dropdown_terminal_button"].show()
        else:
            self.widgets["dropdown_terminal_button"].hide()

    def on_enter_pressed(self):
        tree = self.widgets['tree']
        item = tree.currentItem()
        if item is None:
            return

        path = item.data(0, Qt.ItemDataRole.UserRole)
        if path == "__separator__":
            return

        if os.path.isdir(path) or item.childCount() > 0:
            item.setExpanded(not item.isExpanded())
        else:
            self.open_new_tab_for_tree(item, tree.currentColumn())

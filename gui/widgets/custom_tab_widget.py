from PyQt6.QtWidgets import QTabWidget, QMenu
from PyQt6.QtCore import Qt, QPoint
from PyQt6.QtGui import QAction
import os, subprocess
import keyring
from core.controller import controller_instance
import traceback

class CustomTabWidget(QTabWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setMovable(True)
        self.setTabsClosable(True)
        self.tabCloseRequested.connect(self.close_tab)
        self.currentChanged.connect(self.open_tab)
        self.c = controller_instance

        tabbar = self.tabBar()
        tabbar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        tabbar.customContextMenuRequested.connect(self.on_tab_context_menu)

    def on_tab_context_menu(self, pos: QPoint):
        tabbar = self.tabBar()
        index = tabbar.tabAt(pos)
        if index == -1:
            return

        menu = QMenu(tabbar)

        close_action = QAction("Close tab", menu)
        menu.addAction(close_action)

        close_others_action = QAction("Close Others", menu)
        menu.addAction(close_others_action)

        close_all_action = QAction("Close All", menu)
        menu.addAction(close_all_action)

        close_action.triggered.connect(lambda checked=False, i=index: self.close_tab(i))

        def close_others():
            for i in range(self.count() - 1, -1, -1):
                if i != index:
                    try:
                        self.close_tab(i)
                    except Exception:
                        try:
                            self.removeTab(i)
                        except Exception:
                            pass

        def close_all():
            for i in range(self.count() - 1, -1, -1):
                try:
                    self.close_tab(i)
                except Exception:
                    try:
                        self.removeTab(i)
                    except Exception:
                        pass

        close_others_action.triggered.connect(close_others)
        close_all_action.triggered.connect(close_all)

        global_pos = tabbar.mapToGlobal(pos)
        menu.exec(global_pos)

    def close_tab(self, index):
        try:
            tab_widget = self.widget(index)
        except Exception:
            tab_widget = None
        if tab_widget is None:
            return

        tab_name = None
        container = tab_widget

        path = None
        for path, obj in list(controller_instance.opened_tabs_tree.items()):
            try:
                editor = obj.get("editor")
                if editor is tab_widget or editor == tab_widget:
                    tab_name = path
                    container = editor
                    controller_instance.opened_tabs_tree.pop(path, None)
                    break
            except Exception:
                continue
        else:
            path = None
        if path and os.path.basename(path).lower() == "psnmap.purr":
            try:
                pw = keyring.get_password(self.c.SERVICE, self.c.USER)
                if pw:
                    subprocess.run(
                        ["sudo", "-S", "--", "docker", "rm", "-f", "webmap"],
                        input=pw + "\n",
                        capture_output=True,
                        text=True,
                        check=True,
                    )
            except Exception:
                pass

        try:
            for key, val in list(controller_instance.widgets.items()):
                if val is container:
                    controller_instance.widgets.pop(key, None)
                    break
        except Exception:
            pass

        loader = getattr(container, "_loader", None)
        if loader is not None:
            try:
                if hasattr(loader, "cleanup") and callable(loader.cleanup):
                    try:
                        loader.cleanup()
                    except Exception:
                        pass
            except Exception:
                pass

            try:
                th = getattr(loader, "thread", None)
                if th is not None:
                    try:
                        if hasattr(th, "requestInterruption"):
                            th.requestInterruption()
                        if hasattr(th, "quit"):
                            th.quit()
                        try:
                            th.wait(500)
                        except Exception:
                            if hasattr(th, "join"):
                                try:
                                    th.join(timeout=0.5)
                                except Exception:
                                    pass
                    except Exception:
                        pass

                    try:
                        if hasattr(controller_instance, "threads"):
                            try:
                                controller_instance.threads.remove(th)
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                pass

            try:
                for a in ("thread", "_worker", "temp_pdf_path", "player"):
                    if hasattr(loader, a):
                        try:
                            delattr(loader, a)
                        except Exception:
                            pass
            except Exception:
                pass

            try:
                if hasattr(container, "_loader"):
                    try:
                        delattr(container, "_loader")
                    except Exception:
                        try:
                            del container._loader
                        except Exception:
                            pass
            except Exception:
                pass

        if tab_name is not None:
            try:
                if hasattr(controller_instance, "text_chunks"):
                    controller_instance.text_chunks.pop(tab_name, None)
            except Exception:
                pass

        try:
            self.removeTab(index)
        except Exception:
            try:
                for i in range(self.count()):
                    if self.widget(i) is tab_widget:
                        try:
                            self.removeTab(i)
                        except Exception:
                            pass
                        break
            except Exception:
                pass

        try:
            tab_widget.deleteLater()
        except Exception:
            pass

        try:
            if len(controller_instance.opened_tabs_tree) == 0:
                if "welcome_tab_text" in controller_instance.widgets:
                    try:
                        controller_instance.widgets["welcome_tab_text"].setVisible(True)
                    except Exception:
                        pass
        except Exception:
            pass

        try:
            controller_instance.update_dropdown_menu()
            controller_instance.update_dropdown_visibility()
        except Exception:
            pass

        try:
            controller_instance.save_session()
        except Exception:
            pass

    def open_tab(self, index):

        self.index = index
        controller_instance.update_dropdown_menu()
        controller_instance.update_dropdown_visibility()

    def add_tool_tip(self, name):
        index = self.count() - 1
        self.setTabToolTip(index, name)


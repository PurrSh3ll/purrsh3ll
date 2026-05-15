import logging
import os, re, shutil, subprocess, threading, time
from datetime import datetime
import keyring

logger = logging.getLogger(__name__)

from PyQt6.QtGui import QMovie

from PyQt6.QtWidgets import (
    QWidget,

    QPlainTextEdit,
    QTextEdit,
    QCheckBox,
    QFrame,
    QStackedLayout,
    QComboBox,
    QInputDialog
)

from PyQt6.QtWidgets import (
    QLineEdit
)
from PyQt6.QtWidgets import QStackedWidget

from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineProfile, QWebEngineCookieStore

import json
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QSpinBox,
    QPushButton, QTableWidget, QTableWidgetItem, QMessageBox, QSizePolicy
)
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QSplitter
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QPushButton, QMessageBox
from gui.widgets.custom_line_edit import ExpandingLineEdit
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEnginePage

from PyQt6.QtWidgets import QMenu
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QAction
from PyQt6.QtWebEngineCore import QWebEngineSettings
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import QUrl

def _run_sudo(docker_args: list, password: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["sudo", "-S", "--"] + docker_args,
        input=password + "\n",
        capture_output=True,
        text=True,
        **kwargs,
    )


class WebPreview(QWebEngineView):
    def __init__(self, parent=None):
        super().__init__(parent)

    def contextMenuEvent(self, event):
        """Własne menu kontekstowe z opcjami nawigacji i kopiowania."""
        menu = QMenu(self)

        act_back = QAction("◀ Back", self)
        act_back.triggered.connect(self.back)
        act_back.setEnabled(self.history().canGoBack())
        menu.addAction(act_back)

        act_forward = QAction("Forward ▶", self)
        act_forward.triggered.connect(self.forward)
        act_forward.setEnabled(self.history().canGoForward())
        menu.addAction(act_forward)

        menu.addSeparator()

        act_select_all = QAction("Select all", self)
        act_select_all.triggered.connect(lambda: self.page().triggerAction(QWebEnginePage.WebAction.SelectAll))
        menu.addAction(act_select_all)

        act_copy = QAction("Copy", self)
        act_copy.triggered.connect(lambda: self.page().triggerAction(QWebEnginePage.WebAction.Copy))
        menu.addAction(act_copy)

        act_copy_url = QAction("Copy page URL", self)
        act_copy_url.triggered.connect(self._copy_page_url_to_clipboard)
        menu.addAction(act_copy_url)

        menu.addSeparator()

        act_reload = QAction("Reload", self)
        act_reload.triggered.connect(self.reload)
        menu.addAction(act_reload)

        menu.exec(event.globalPos())

    def _copy_page_url_to_clipboard(self):
        """Kopiuj aktualny adres strony do schowka."""
        url = self.url().toString()
        if url:
            QGuiApplication.clipboard().setText(url)

class AddProfileDialog(QDialog):
    """Dialog do dodania nowego profilu z walidacją"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add new profile")
        self.setModal(True)
        self.resize(400, 200)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Profile Name:"))
        self.name_input = QLineEdit()
        name_layout.addWidget(self.name_input)
        layout.addLayout(name_layout)

        command_layout = QHBoxLayout()
        command_layout.addWidget(QLabel("Command:"))
        self.command_input = QLineEdit()
        command_layout.addWidget(self.command_input)
        layout.addLayout(command_layout)

        desc_layout = QHBoxLayout()
        desc_layout.addWidget(QLabel("Description:"))
        self.desc_input = QLineEdit()
        desc_layout.addWidget(self.desc_input)
        layout.addLayout(desc_layout)

        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(self.accept)
        layout.addWidget(btn_ok, alignment=Qt.AlignmentFlag.AlignRight)

        self.setLayout(layout)

    def accept(self):
        """Validation before closing"""
        name = self.name_input.text().strip()
        command = self.command_input.text().strip()

        if not name:
            QMessageBox.warning(self, "Error", "'Profile Name' field cannot be empty!")
            return
        if not command:
            QMessageBox.warning(self, "Error", "'Command' field cannot be empty!")
            return

        parent = self.parent()
        if parent:
            profiles = parent.parsed_data.get("profiles", [])
            if any(p.get("profile_name", "").strip() == name for p in profiles):
                QMessageBox.warning(self, "Error", f"Profile named '{name}' already exists!")
                return

        super().accept()

    def get_data(self):
        """Zwraca dane wpisane przez użytkownika"""
        return {
            "profile_name": self.name_input.text().strip(),
            "command": self.command_input.text().strip(),
            "description": self.desc_input.text().strip()
        }

class PsnmapOptionsDialog(QDialog):
    def __init__(self, parsed_data, path, parent=None):
        super().__init__(parent)
        self.parsed_data = parsed_data
        self.path = path
        self.parent = parent

        self.setWindowTitle("psnmap options")
        self.setModal(True)
        self.resize(700, 400)

        self.init_ui()

    def load_port(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
                port = data.get("port", 1)
                self.port_input.setValue(port)
        except Exception as e:
            logger.error("Error loading port data", exc_info=True)

    def init_ui(self):
        layout = QVBoxLayout()

        port_layout = QHBoxLayout()
        label = QLabel("Visualizer Port:")
        label.setFixedWidth(120)

        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setFixedWidth(80)
        self.port_input.setAlignment(Qt.AlignmentFlag.AlignCenter)

        ok_button = QPushButton("OK")
        ok_button.setFixedWidth(50)
        ok_button.clicked.connect(self.validate_port)

        clear_history_button = QPushButton("Clear history")
        clear_history_button.clicked.connect(self.clear_history)

        clear_profiles_button = QPushButton("Clear profiles")
        clear_profiles_button.clicked.connect(self.clear_profiles)

        add_button = QPushButton("➕")
        add_button.setFixedWidth(50)
        add_button.clicked.connect(self.add_profile)

        port_layout.addWidget(label)
        port_layout.addWidget(self.port_input)
        port_layout.addWidget(ok_button)
        port_layout.addWidget(clear_history_button)
        port_layout.addWidget(clear_profiles_button)
        port_layout.addWidget(add_button)
        port_layout.addStretch()

        layout.addLayout(port_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["profile", "command", "description", "action"])
        self.table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, header.ResizeMode.Interactive)
        header.setSectionResizeMode(1, header.ResizeMode.Interactive)
        header.setSectionResizeMode(2, header.ResizeMode.Stretch)
        header.setSectionResizeMode(3, header.ResizeMode.Fixed)
        self.table.setColumnWidth(3, 50)

        self.load_data()
        layout.addWidget(self.table)

        self.setLayout(layout)
        self.load_port()

    def validate_port(self):
        port = self.port_input.value()
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["port"] = port
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            self.parsed_data["port"] = port
            QMessageBox.information(self, "OK", f"Saved port number: {port}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Can't save:\n{e}")

    def load_data(self):
        profiles = self.parsed_data.get("profiles", [])
        self.table.setRowCount(len(profiles))

        for row, profile in enumerate(profiles):
            self.table.setItem(row, 0, QTableWidgetItem(profile.get("profile_name", "")))
            self.table.setItem(row, 1, QTableWidgetItem(profile.get("command", "")))
            self.table.setItem(row, 2, QTableWidgetItem(profile.get("description", "")))

            btn = QPushButton("❌")
            btn.setFixedWidth(40)
            btn.clicked.connect(lambda checked, r=row: self.delete_profile(r))
            self.table.setCellWidget(row, 3, btn)

    def delete_profile(self, row):
        profiles = self.parsed_data.get("profiles", [])
        if row < 0 or row >= len(profiles):
            return

        profile = profiles[row]
        confirm = QMessageBox.question(
            self, "Confirm Deletion",
            f"Are you sure you want to delete the profile '{profile.get('profile_name', '')}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if confirm == QMessageBox.StandardButton.Yes:
            del profiles[row]
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data["profiles"] = profiles
                with open(self.path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
                self.load_data()
                self.parent.refresh_profiles()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save changes:\n{e}")

    def add_profile(self):
        """Opens a dialog to add a new profile"""
        dialog = AddProfileDialog(self)
        if dialog.exec():
            new_profile = dialog.get_data()

            profiles = self.parsed_data.get("profiles", [])
            new_profile["id"] = max([p.get("id", 0) for p in profiles], default=0) + 1
            profiles.append(new_profile)

            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data["profiles"] = profiles
                with open(self.path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
                self.load_data()
                self.parent.refresh_profiles()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save changes:\n{e}")

    def clear_history(self):
        reply = QMessageBox.question(self, "Clear history",
                                     "Are you sure you want to delete all history entries?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["history"] = []
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            self.parsed_data["history"] = []
            self.parent._refresh_history_table()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to clear history:\n{e}")

    def clear_profiles(self):
        reply = QMessageBox.question(self, "Clear profiles",
                                     "Are you sure you want to delete all profiles?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["profiles"] = []
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            self.parsed_data["profiles"] = []
            self.load_data()
            self.parent.refresh_profiles()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to clear profiles:\n{e}")

class ScriptLauncher(QWidget):

    def __init__(self, parent=None, controller = None, path: str | None = None, data = None):
        super().__init__(parent=parent)
        self.path = path
        self.controller = controller
        self.webmap_dir = os.path.join(self.controller.base_path, "appmodules", "Cyb3rCollector", "webmap")
        self.controller_term_tabs = self.controller.widgets["terminal_tabs"]
        self.data = data
        self.parsed_data = json.loads(self.data)
        self.profiles = self.parsed_data.get("profiles", [])

        self.name = os.path.splitext(os.path.basename(self.path))[0]
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.visualization_text = "Enable WebMap using the button aside to see the visualization. Note: This may slow down app performance."
        self.history_text = "[-] Execution history is empty. The program has not been launched yet."
        self.help_text = "[-] MD HELP HERE"

        self._build_ui()

    @property
    def detail_texts(self):
        return         {
            "visualization": self.visualization_text,
            "history": self.history_text,
            "help": self.help_text,
        }

    def refresh_profiles(self):
        """
        Refresh the profile_combo to reflect the current profiles in self.parsed_data.
        Call this after adding/deleting profiles in the JSON.
        """
        self.profiles = self.parsed_data.get("profiles", [])

        current_name = self.profile_combo.currentText()

        self.profile_combo.clear()
        self.profile_map.clear()

        for profile in self.profiles:
            name = profile.get("profile_name", "unknown")
            command = profile.get("command", "")
            self.profile_combo.addItem(name)
            self.profile_map[name] = command

        if current_name in self.profile_map:
            index = self.profile_combo.findText(current_name)
            if index >= 0:
                self.profile_combo.setCurrentIndex(index)
        else:
            if self.profile_combo.count() > 0:
                self.profile_combo.setCurrentIndex(0)

        self._update_terminal_input()

    def open_settings_dialog(self):
        dialog = PsnmapOptionsDialog(self.parsed_data, self.path, self)
        dialog.exec()

    def _execute_external_term(self, command):
        TERMINAL_CANDIDATES = [
            "qterminal",
            "gnome-terminal",
            "xfce4-terminal",
            "konsole",
            "xterm",
            "tilix",
            "lxterminal",
            "terminator",
            "mate-terminal",
            "kitty",
            "alacritty",
        ]

        def _find_available_terminal():
            for t in TERMINAL_CANDIDATES:
                if shutil.which(t):
                    return t
            return None

        def _clean_env_remove_venv() -> dict:
            env = os.environ.copy()
            venv = env.pop("VIRTUAL_ENV", None)
            env.pop("PYTHONPATH", None)
            env.pop("PYENV_VERSION", None)
            if venv:
                venv_bin = os.path.join(venv, "bin")
                path_parts = env.get("PATH", "").split(":")
                path_parts = [p for p in path_parts if os.path.abspath(p) != os.path.abspath(venv_bin)]
                env["PATH"] = ":".join(path_parts)
            env.pop("QT_QPA_PLATFORMTHEME", None)
            env["QT_LOGGING_RULES"] = "qt.qpa.*=false"
            return env

        def open_clean_terminal_nonblocking_paste(command: str | None):
            """
            Otwiera nowy terminal w tle i (jeśli xdotool dostępny) wkleja `command` do terminala
            bez jego automatycznego wykonania. Jeżeli `command` zawiera '\n' to po wklejeniu
            dodatkowo wyśle Enter (wykona).
            """

            def worker():
                term = _find_available_terminal()
                if not term:
                    return

                home = os.path.expanduser("~")
                env = _clean_env_remove_venv()

                try:
                    subprocess.Popen([term], cwd=home, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception as e:
                    logger.error("Failed to open terminal", exc_info=True)
                    return

                if not command:
                    return

                if not shutil.which("xdotool"):
                    return

                time.sleep(0.5)

                found_win = None
                try:
                    cls_candidates = [term, term.replace("-", ""), term.capitalize()]
                    win_ids = []
                    for cls in cls_candidates:
                        try:
                            out = subprocess.check_output(["xdotool", "search", "--onlyvisible", "--class", cls],
                                                          stderr=subprocess.DEVNULL)
                            ids = out.decode().strip().splitlines()
                            if ids:
                                win_ids.extend(ids)
                        except subprocess.CalledProcessError:
                            pass
                    if not win_ids:
                        out = subprocess.check_output(["xdotool", "search", "--onlyvisible", "--name", "."],
                                                      stderr=subprocess.DEVNULL)
                        win_ids = out.decode().strip().splitlines()

                    if win_ids:
                        found_win = win_ids[-1]
                except Exception:
                    found_win = None

                if not found_win:
                    return

                try:
                    subprocess.call(["xdotool", "windowactivate", found_win], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
                    time.sleep(0.05)
                except Exception:
                    pass

                has_newline = "\n" in command
                to_type = command

                if not has_newline:
                    to_type = command.replace("\r", "").replace("\n", "")

                try:
                    subprocess.call(["xdotool", "type", "--delay", "0", "--window", found_win, to_type],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                except Exception as e:
                    logger.error("xdotool type failed", exc_info=True)
                    return

                if has_newline:
                    if not (command.endswith("\n") or command.endswith("\r\n")):
                        time.sleep(0.05)
                        try:
                            subprocess.call(["xdotool", "key", "--window", found_win, "Return"],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        except Exception:
                            pass

            threading.Thread(target=worker, daemon=True).start()
        open_clean_terminal_nonblocking_paste(command)

    def _append_history(self, command):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            entry = {
                "profile_name": self.profile_combo.currentText(),
                "command": command.strip(),
                "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            data.setdefault("history", []).append(entry)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logger.warning("Failed to append history", exc_info=True)

    def _execute_command(self, command):
        self._append_history(command)

        if self.chk_run_external.isChecked():
            self._execute_external_term(command)
            return

        try:
            if command.endswith("\n"):
                cmd_clean = command.rstrip("\n")

        except Exception:
            pass

        terminal_tabs = self.controller.widgets["terminal_tabs"]

        if self.chk_run_current.isChecked():
            pattern = re.compile(rf"{re.escape(self.name)}\s+(\d+)", flags=re.IGNORECASE)
            best_idx = None
            best_num = -1

            for i in range(self.controller_term_tabs.count()):
                tab_label = self.controller_term_tabs.tabText(i)
                m = pattern.search(tab_label)
                if m:
                    try:
                        num = int(m.group(1))
                    except Exception:
                        continue
                    if num > best_num:
                        best_num = num
                        best_idx = i

            if best_idx is not None:
                wrapper = self.controller_term_tabs.widget(best_idx)
                term = self.controller.wrapper_to_console.get(wrapper)
                if term:
                    terminal_tabs.setCurrentIndex(best_idx)

                    term.sendText(command)
                    return

        self.controller.purr_term_numb += 1
        new_name = f"{self.name} {self.controller.purr_term_numb}"

        self.controller.console_args = {"name": new_name, "command": command}
        self.controller.widgets["btn_add_console"].click()
        self.controller.console_args.clear()

        last_idx = terminal_tabs.count() - 1
        if last_idx >= 0:
            terminal_tabs.setCurrentIndex(last_idx)
        return

    def check_docker(self, user_password, container_name):
        report = {
            "password": True,
            "container": False,
            "running": False,
            "port": False
        }

        try:
            result = _run_sudo([
                "docker", "ps",
                "--filter", f"name={container_name}",
                "--format", "{{.Ports}}",
            ], user_password)

            if "incorrect password" in result.stderr.lower() or "sorry, try again" in result.stderr.lower():
                report["password"] = False
                return report

            output = result.stdout.strip()
            if output:
                report["container"] = True
                report["running"] = True
                port_match = re.search(r':(\d+)->', output)
                if port_match:
                    report["port"] = port_match.group(1)
                return report

            exists_check = _run_sudo([
                "docker", "ps", "-a",
                "--filter", f"name={container_name}",
                "--format", "{{.Names}}",
            ], user_password)

            if container_name in exists_check.stdout:
                report["container"] = True
                report["running"] = False

                inspect_result = _run_sudo([
                    "docker", "inspect",
                    "--format", "{{range $p, $conf := .HostConfig.PortBindings}}{{(index $conf 0).HostPort}}{{end}}",
                    container_name,
                ], user_password)

                found_port = inspect_result.stdout.strip()

                if found_port:
                    report["port"] = found_port
                else:
                    report["port"] = False
            else:
                report["container"] = False

            return report

        except Exception as e:
            logger.error("System error during report generation", exc_info=True)
            return report

    def _toggle_network_button(self, checked):
        if checked:
            if not self._ensure_root_password():
                self.network_button.setChecked(False)
                return

            docker_status = self._check_docker_status_with_retry("webmap")
            if docker_status is None:
                self.network_button.setChecked(False)
                return

            should_start_webview = self._handle_docker_status(docker_status)
            if not should_start_webview:
                self.network_button.setChecked(False)
                return

            self.network_button.setChecked(True)
            self.token_button.setVisible(True)
            self._start_webview()

        else:
            self._handle_disable_action()

    def _ensure_root_password(self):
        SERVICE = self.controller.SERVICE
        USER = self.controller.USER

        root_pw = keyring.get_password(SERVICE, USER)

        if root_pw is None:
            pw, ok = QInputDialog.getText(
                self,
                "Enter Password",
                "Please enter the root password",
                QLineEdit.EchoMode.Password
            )
            if ok and pw:
                keyring.set_password(SERVICE, USER, pw)
                return True
            return False

        return True

    def _check_docker_status_with_retry(self, container_name):
        SERVICE = self.controller.SERVICE
        USER = self.controller.USER

        pw = keyring.get_password(SERVICE, USER)
        docker_status = self.check_docker(pw, container_name)

        if not docker_status["password"]:
            QMessageBox.critical(
                self,
                "Authentication Error",
                "Invalid root password. Please try again."
            )

            pw, ok = QInputDialog.getText(
                self,
                "Enter Password",
                "Please enter the root password",
                QLineEdit.EchoMode.Password
            )

            if ok and pw:
                keyring.set_password(SERVICE, USER, pw)
                docker_status = self.check_docker(pw, container_name)

                if not docker_status["password"]:
                    QMessageBox.critical(
                        self,
                        "Authentication Error",
                        "Invalid password again. Operation aborted."
                    )
                    return None
            else:
                return None

        return docker_status

    def _handle_docker_status(self, docker_status):
        """
        Obsługa stanu kontenera i portu.
        Zwraca True jeśli można startować WebView,
        False jeśli port niezgodny (popup),
        w przeciwnym razie startuje kontener jeśli STOPPED + port zgodny,
        lub tworzy i uruchamia nowy kontener jeśli nie istnieje.
        """
        expected_port = str(self.parsed_data.get("port", ""))
        pw = keyring.get_password(self.controller.SERVICE, self.controller.USER)

        if not docker_status["container"]:

            try:
                _run_sudo([
                    "docker", "run", "-d",
                    "--name", "webmap",
                    "-h", "webmap",
                    "-p", f"{expected_port}:8000",
                    "-v", f"{self.webmap_dir}:/opt/xml",
                    "reborntc/webmap",
                ], pw, check=True)
            except subprocess.CalledProcessError as e:
                logger.error("Failed to create/start container 'webmap': %s", e.stderr)
                QMessageBox.critical(self, "Container Creation Failed",
                                     f"Failed to create/start container 'webmap'.\n{e.stderr}")
                return False

            return True

        actual_port = str(docker_status.get("port", "None"))

        if actual_port != expected_port:
            msg = (
                f"⚠️ Container 'webmap' port mismatch.\n"
                f"Detected port: {actual_port}\n"
                f"Expected port: {expected_port}\n\n"
                "The port does not match the application configuration.\n"
                "You should remove this container before continuing."
            )
            QMessageBox.critical(self, "Port Mismatch", msg)
            return False

        if not docker_status["running"]:
            try:
                _run_sudo(["docker", "start", "webmap"], pw, check=True)
            except subprocess.CalledProcessError as e:
                logger.error("Failed to start container 'webmap': %s", e.stderr)
                QMessageBox.critical(self, "Start Failed", f"Failed to start container 'webmap'.\n{e.stderr}")
                return False

        else:
            pass

        return True

    def _start_webview(self):
        self._clear_layout()

        self.network_button.setText("⛔")

        self.web_preview = WebPreview(self)
        token = "0XTgjEMNUYb7"
        js_code = f'localStorage.setItem("sessionToken", "{token}");'
        self.web_preview.page().runJavaScript(js_code)

        self.web_preview.setUrl(QUrl("http://127.0.0.1:8000/"))
        self.visualization_layout.addWidget(self.web_preview)

    def _clear_layout(self):
        while self.visualization_layout.count():
            item = self.visualization_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)

    def _handle_disable_action(self):
        """
        Pokazuje okno z opcjami Do Nothing / Stop / Shutdown.
        Stopuje lub usuwa kontener w osobnym wątku, aby nie blokować GUI.
        """
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("WebMap Service Control")
        msg_box.setText("What do you want to do with WebMap?")
        msg_box.setIcon(QMessageBox.Icon.Question)

        do_nothing_btn = msg_box.addButton("Nothing", QMessageBox.ButtonRole.RejectRole)
        stop_btn = msg_box.addButton("Stop", QMessageBox.ButtonRole.AcceptRole)
        remove_btn = msg_box.addButton("Shutdown", QMessageBox.ButtonRole.DestructiveRole)

        msg_box.exec()
        clicked = msg_box.clickedButton()

        pw = keyring.get_password(self.controller.SERVICE, self.controller.USER)

        def run_docker_command(docker_args, error_title=None):
            def worker():
                try:
                    _run_sudo(docker_args, pw, check=True)
                except subprocess.CalledProcessError as e:
                    if error_title:
                        QMessageBox.critical(self, error_title, str(e.stderr))

            threading.Thread(target=worker, daemon=True).start()

        if clicked == stop_btn or clicked == remove_btn:
            self._clear_layout()
            self.network_button.setText("🌐")
            self.token_button.setVisible(False)

            if hasattr(self, "web_preview"):
                self.web_preview.deleteLater()
                self.web_preview = None

            self.visualization_layout.addWidget(self.visualization_text_widget)

            if clicked == stop_btn:
                run_docker_command(
                    ["docker", "stop", "webmap"],
                    error_title="Stop Failed",
                )

            elif clicked == remove_btn:
                run_docker_command(
                    ["docker", "rm", "-f", "webmap"],
                    error_title="Remove Failed",
                )

        else:
            self.network_button.setChecked(True)

    def _update_terminal_input(self):
        profile_name = self.profile_combo.currentText()
        base_command = self.profile_map.get(profile_name, "")

        target = self.target_input.text().strip()

        cmd = f"{base_command} {target}".strip()

        if hasattr(self, 'chk_save_result') and self.chk_save_result.isChecked():
            if cmd.startswith("sudo "):
                cmd = "sudo xmlwrap " + cmd[5:]
            else:
                cmd = "xmlwrap " + cmd

        self.terminal_input.setPlainText(cmd)

    def _show_token(self):
        """Wykonuje 'docker exec webmap /root/token' i pokazuje output w modalnym oknie."""
        pw = keyring.get_password(self.controller.SERVICE, self.controller.USER)

        try:
            result = _run_sudo(
                ["docker", "exec", "webmap", "/root/token"],
                pw,
                timeout=15,
            )
            output = result.stdout.strip() or result.stderr.strip() or "(no output)"
        except subprocess.TimeoutExpired:
            output = "❌ Command timed out after 15 seconds."
        except Exception as e:
            output = f"❌ Error: {e}"

        token_value = output.removeprefix("Token: ").strip()

        dialog = QDialog(self)
        dialog.setWindowTitle("WebMap Token")
        dialog.setModal(True)
        dialog.setFixedSize(380, 110)

        layout = QVBoxLayout(dialog)
        layout.setSpacing(6)
        layout.setContentsMargins(12, 10, 12, 10)

        copy_label = QLabel("Copy token below", dialog)
        layout.addWidget(copy_label)

        row = QHBoxLayout()
        token_field = QLineEdit(dialog)
        token_field.setReadOnly(True)
        token_field.setText(token_value)
        token_field.mousePressEvent = lambda e: token_field.selectAll()
        row.addWidget(token_field)

        copy_btn = QPushButton("Copy", dialog)
        copy_btn.setFixedWidth(60)
        copy_btn.clicked.connect(lambda: QGuiApplication.clipboard().setText(token_value))
        row.addWidget(copy_btn)
        layout.addLayout(row)

        dialog.exec()

    def _build_ui(self):

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(6, 6, 6, 6)
        root_layout.setSpacing(6)
        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(6)

        self.target_input = QLineEdit(self)
        self.target_input.setPlaceholderText("target")
        self.target_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.target_input.setFixedHeight(28)

        top_row.addWidget(self.target_input, 1)

        self.profile_combo = QComboBox(self)
        self.profile_combo.setFixedWidth(250)
        self.profile_combo.setFixedHeight(28)

        self.profile_map = {}

        for profile in self.profiles:
            name = profile.get("profile_name", "unknown")
            command = profile.get("command", "")

            self.profile_combo.addItem(name)
            self.profile_map[name] = command

        top_row.addWidget(self.profile_combo)

        self.settings_button = QPushButton("⚙", self)
        self.settings_button.setFixedSize(32, 28)
        self.settings_button.clicked.connect(self.open_settings_dialog)
        top_row.addWidget(self.settings_button)

        self.token_button = QPushButton("🔑", self)
        self.token_button.setFixedSize(32, 28)
        self.token_button.setVisible(False)
        self.token_button.clicked.connect(self._show_token)
        top_row.addWidget(self.token_button)

        self.network_button = QPushButton("🌐", self)
        self.network_button.setFixedSize(32, 28)
        self.network_button.setCheckable(True)
        self.network_button.clicked.connect(self._toggle_network_button)
        top_row.addWidget(self.network_button)

        root_layout.addLayout(top_row)

        buttons_row = QHBoxLayout()
        buttons_row.setContentsMargins(0, 0, 0, 0)
        buttons_row.setSpacing(6)

        self.visualization_button = QPushButton("visualization", parent=self)
        self.history_button = QPushButton("history", parent=self)
        self.help_button = QPushButton("help", parent=self)
        self.buttons = [self.visualization_button, self.history_button, self.help_button]
        checkable_names = {"visualization", "history", "help"}
        for button in self.buttons:
            button.setFixedHeight(28)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

            if button.text() in checkable_names:
                button.setCheckable(True)
                button.clicked.connect(lambda checked, b=button: self._on_checkable_clicked(b))
            else:
                button.setCheckable(False)

            buttons_row.addWidget(button)

        root_layout.addLayout(buttons_row)

        self.central_container = QWidget(self)
        self.central_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.central_layout = QVBoxLayout(self.central_container)
        self.central_layout.setContentsMargins(0, 0, 0, 0)
        self.central_layout.setSpacing(0)

        self.central_stack = QStackedWidget()

        self.welcome_field = QLabel()
        self.welcome_field.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.movie = QMovie(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "icons", "psnmap.gif"))
        self.welcome_field.setMovie(self.movie)
        self.movie.start()

        self.detail_field = QTextEdit()
        self.detail_field.setReadOnly(True)
        self.detail_field.setObjectName("docs")
        self.detail_field.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.detail_field.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.help_field = QTextEdit()
        self.help_field.setReadOnly(True)
        self.help_field.setObjectName("docs")
        self.help_field.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.help_field.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        help_md_path = os.path.join(self.controller.base_path, "appdata", "psnmap_help.md")
        try:
            with open(help_md_path, "r", encoding="utf-8") as f:
                self.help_field.setMarkdown(f.read())
        except Exception as e:
            self.help_field.setPlainText(f"Could not load help file:\n{e}")

        self.visualization_field = QWidget()
        self.visualization_layout = QVBoxLayout(self.visualization_field)
        self.visualization_layout.setContentsMargins(0, 0, 0, 0)
        self.visualization_text_widget = QTextEdit()
        self.visualization_text_widget.setReadOnly(True)
        self.visualization_text_widget.setPlainText(
            "Enable WebMap using the button aside to see the visualization. Note: This may slow down app performance."
        )

        self.visualization_layout.addWidget(self.visualization_text_widget)

        self.history_field = QTableWidget()
        self.history_field.setObjectName("history_table")
        self.history_field.setColumnCount(4)
        self.history_field.setHorizontalHeaderLabels(["#", "Profile", "Command", "Date & Time"])
        self.history_field.horizontalHeader().setStretchLastSection(False)
        self.history_field.horizontalHeader().setSectionResizeMode(0, self.history_field.horizontalHeader().ResizeMode.ResizeToContents)
        self.history_field.horizontalHeader().setSectionResizeMode(1, self.history_field.horizontalHeader().ResizeMode.ResizeToContents)
        self.history_field.horizontalHeader().setSectionResizeMode(2, self.history_field.horizontalHeader().ResizeMode.Stretch)
        self.history_field.horizontalHeader().setSectionResizeMode(3, self.history_field.horizontalHeader().ResizeMode.ResizeToContents)
        self.history_field.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history_field.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history_field.verticalHeader().setVisible(False)
        self.history_field.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.central_layout.addWidget(self.central_stack, 1)
        root_layout.addWidget(self.central_container, 1)
        self.central_stack.addWidget(self.welcome_field)
        self.central_stack.addWidget(self.visualization_field)
        self.central_stack.addWidget(self.history_field)
        self.central_stack.addWidget(self.help_field)

        self.central_stack.setCurrentWidget(self.welcome_field)

        sep1 = QFrame(self)
        sep1.setFrameShape(QFrame.Shape.HLine)
        sep1.setFrameShadow(QFrame.Shadow.Sunken)
        sep1.setObjectName("line")
        root_layout.addWidget(sep1)
        row1 = QHBoxLayout()
        row1.setContentsMargins(0, 0, 0, 0)
        row1.setSpacing(12)

        row1.addStretch(1)
        root_layout.addLayout(row1)
        row2 = QHBoxLayout()
        row2.setContentsMargins(0, 0, 0, 0)
        row2.setSpacing(12)

        lbl_external = QLabel("External Terminal", parent=self)
        self.chk_run_external = QCheckBox(parent=self)
        row2.addWidget(lbl_external)
        row2.addWidget(self.chk_run_external)

        def _on_external_toggled(checked):
            if checked:
                self.chk_run_current.setChecked(False)

        self.chk_run_external.toggled.connect(_on_external_toggled)

        lbl_run_current = QLabel("Keep Session", parent=self)
        self.chk_run_current = QCheckBox(parent=self)
        row2.addWidget(lbl_run_current)
        row2.addWidget(self.chk_run_current)

        def _on_current_toggled(checked):
            if checked:
                self.chk_run_external.setChecked(False)

        self.chk_run_current.toggled.connect(_on_current_toggled)
        save_result = QLabel("WebMap Export", parent=self)
        self.chk_save_result = QCheckBox(parent=self)
        row2.addWidget(save_result)
        row2.addWidget(self.chk_save_result)

        self.chk_save_result.toggled.connect(lambda _: self._update_terminal_input())

        row2.addStretch(1)
        root_layout.addLayout(row2)
        sep2 = QFrame(self)
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setFrameShadow(QFrame.Shadow.Sunken)
        sep2.setObjectName("line")
        root_layout.addWidget(sep2)
        self.advanced_widget = QWidget(parent=self)
        adv_layout = QVBoxLayout(self.advanced_widget)
        adv_layout.setContentsMargins(0, 0, 0, 0)
        adv_layout.setSpacing(6)
        row3 = QHBoxLayout()
        row3.setContentsMargins(0, 0, 0, 0)
        row3.setSpacing(12)

        row3.addStretch(1)
        adv_layout.addLayout(row3)

        sep3 = QFrame(self.advanced_widget)
        sep3.setFrameShape(QFrame.Shape.HLine)
        sep3.setFrameShadow(QFrame.Shadow.Sunken)
        sep3.setObjectName("line")
        adv_layout.addWidget(sep3)
        self.advanced_widget.setVisible(False)
        root_layout.addWidget(self.advanced_widget)
        bottom_row = QHBoxLayout()
        bottom_row.setContentsMargins(0, 0, 0, 0)
        bottom_row.setSpacing(6)

        self.terminal_input = QPlainTextEdit(self)
        self.terminal_input.setObjectName("script_term")
        self.terminal_input.setFixedHeight(36)
        self.terminal_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        bottom_row.addWidget(self.terminal_input)

        enter_btn = QPushButton("⏎", self)
        enter_btn.setFixedSize(40, 36)
        paste_btn = QPushButton("⧉", self)
        paste_btn.setFixedSize(60, 36)
        enter_btn.clicked.connect(lambda: self._execute_command((self.terminal_input.toPlainText() or "") + "\n"))
        paste_btn.clicked.connect(lambda: self._execute_command(self.terminal_input.toPlainText() or ""))
        bottom_row.addWidget(enter_btn)
        bottom_row.addWidget(paste_btn)
        root_layout.addLayout(bottom_row)

        self.profile_combo.currentTextChanged.connect(self._update_terminal_input)
        self.target_input.textChanged.connect(self._update_terminal_input)

        self._update_terminal_input()

    def _refresh_history_table(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            entries = data.get("history", [])
        except Exception:
            entries = []

        self.history_field.setRowCount(len(entries))
        for row, entry in enumerate(reversed(entries)):
            for col, text in enumerate([
                str(row + 1),
                entry.get("profile_name", ""),
                entry.get("command", ""),
                entry.get("datetime", ""),
            ]):
                lbl = QLabel(text)
                lbl.setContentsMargins(4, 0, 4, 0)
                self.history_field.setCellWidget(row, col, lbl)

    def _on_checkable_clicked(self, button: QPushButton):
        name = button.text().lower()
        currently_checked = button.isChecked()

        field_map = {
            "visualization": getattr(self, "visualization_field", None),
            "history": getattr(self, "history_field", None),
            "help": getattr(self, "help_field", None),
        }

        if currently_checked:
            for b in self.buttons:
                if b is not button and b.isCheckable():
                    b.setChecked(False)

            target_widget = field_map.get(name)

            if target_widget is not None:
                if name == "history":
                    self._refresh_history_table()
                elif name == "help":
                    pass
                else:
                    text_attr = f"{name}_text"
                    text = getattr(self, text_attr, "")

                    try:
                        target_widget.setPlainText(text)
                    except AttributeError:
                        if hasattr(target_widget, "setText"):
                            target_widget.setText(text)

                self.central_stack.setCurrentWidget(target_widget)

            else:
                self.central_stack.setCurrentWidget(self.welcome_field)

        else:
            any_checked = any(b.isCheckable() and b.isChecked() for b in self.buttons)
            if not any_checked:
                self.central_stack.setCurrentWidget(self.welcome_field)
import os, re, shutil, subprocess, threading, signal, resource, tempfile, time
import csv
from datetime import datetime

class ExecutionMixin:
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

            def worker():
                term = _find_available_terminal()
                if not term:
                    return

                home = os.path.expanduser("~")
                env = _clean_env_remove_venv()

                try:
                    subprocess.Popen([term], cwd=home, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception as e:
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

    def _execute_command(self, command):
        if self.chk_run_external.isChecked():
            self._execute_external_term(command)
            return

        try:
            if command.endswith("\n"):
                cmd_clean = command.rstrip("\n")
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                with open(self.script_history_path, "a", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([cmd_clean, now])
                    self.history_field.update_data_async()

        except Exception:
            pass

        terminal_tabs = self.controller.widgets["terminal_tabs"]

        if self.chk_run_current.isChecked():
            pattern = re.compile(rf"{re.escape(self.name)}\.py\s+(\d+)", flags=re.IGNORECASE)
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
        new_name = f"{self.name}.py {self.controller.purr_term_numb}"

        self.controller.console_args = {"name": new_name, "command": command}
        self.controller.widgets["btn_add_console"].click()
        self.controller.console_args.clear()

        last_idx = terminal_tabs.count() - 1
        if last_idx >= 0:
            terminal_tabs.setCurrentIndex(last_idx)
        return

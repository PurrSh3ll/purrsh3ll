import os
import re
import logging

from PyQt6.QtWidgets import QPushButton

logger = logging.getLogger(__name__)


class HandlersMixin:
    def term_recived_data(self, data):
        if isinstance(data, bytes):
            text = data.decode("utf-8", errors="replace")
        else:
            text = str(data)

        text = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', text)

        text = text.replace('\r\n', '\n').replace('\r', '\n')

        self._term_buffer += text
        if len(self._term_buffer) > self._max_buf:
            cut = len(self._term_buffer) - self._max_buf
            self._term_buffer = self._term_buffer[-self._max_buf:]
            self._last_processed_cmd_end = max(0, self._last_processed_cmd_end - cut)
            self._last_processed_out_end = max(0, self._last_processed_out_end - cut)

        buf = self._term_buffer

        cmd_matches = list(self._cmd_re.finditer(buf))
        last_new_cmd = None
        for m in cmd_matches:
            if m.end() > self._last_processed_cmd_end:
                last_new_cmd = m

        if last_new_cmd:
            search_start = last_new_cmd.end()
            out_match = self._out_re.search(buf, pos=search_start)
            if out_match:
                self.btn_refresh_interpreter.click()
                self._last_processed_cmd_end = out_match.end()
                self._last_processed_out_end = out_match.end()
                self._term_buffer = buf[out_match.end():]
                return

        out_matches = list(self._out_re.finditer(buf))
        if out_matches:
            last_out = out_matches[-1]
            if last_out.end() > self._last_processed_out_end:
                line_start = buf.rfind('\n', 0, last_out.start()) + 1
                prefix = buf[line_start:last_out.start()].strip()
                if 'echo' not in prefix:
                    self.btn_refresh_interpreter.click()
                    self._last_processed_out_end = last_out.end()
                    self._last_processed_cmd_end = max(self._last_processed_cmd_end, last_out.end())
                    self._term_buffer = buf[last_out.end():]
                    return

    def _on_install_clicked(self):
        if self.missing_libs is None:
            return
        command = f'{self.cmb_interpreter.currentText().strip()} -m pip install {self.missing_libs} --break-system-packages && echo "PurrSh3ll has ended >> instalation"\n'

        for i in range(self.controller_term_tabs.count()):
            tab_label = self.controller_term_tabs.tabText(i)
            if tab_label == "PurrSh3ll pip":
                wrapper = self.controller_term_tabs.widget(i)
                term = self.controller.wrapper_to_console.get(wrapper)
                term.receivedData.connect(self.term_recived_data)
                term.sendText(command)
                return

        self.controller.console_args ={"name": "PurrSh3ll pip", "command": command}
        self.controller.widgets["btn_add_console"].click()
        self.controller.console_args.clear()
        for i in range(self.controller_term_tabs.count()):
            tab_label = self.controller_term_tabs.tabText(i)
            if tab_label == "PurrSh3ll pip":
                wrapper = self.controller_term_tabs.widget(i)
                term = self.controller.wrapper_to_console.get(wrapper)
                term.receivedData.connect(self.term_recived_data)
                return

    def _on_file_changed_on_disk(self, path: str):
        """Called by QFileSystemWatcher when the file is modified on disk.

        Editors that use atomic save (PyCharm, VS Code) replace the file via
        rename, which removes it from the watcher. Re-add the path so future
        changes are still detected.
        """
        if os.path.isfile(path):
            if path not in self._file_watcher.files():
                self._file_watcher.addPath(path)
            try:
                self.file_mtime = os.path.getmtime(path)
            except OSError:
                pass
            self.update_help()

    def _on_checkable_clicked(self, button: QPushButton):
        name = button.text().lower()
        currently_checked = button.isChecked()

        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            mtime = None

        if name == "readme":
            self.update_readme()

        if mtime is not None and mtime != getattr(self, "file_mtime", None):
            self.file_mtime = mtime
            self.update_help()

        if name == "code" and not hasattr(self, "_code_widget"):
            from file_loaders.python_file import Python_file
            loader = Python_file()
            self._code_widget = loader.load_file(
                self.path,
                parent=self.controller,
                target_widget=None,
                threads_list=self.controller.threads
            )
            # load_file returns the scroll container; keep the loader itself too so
            # Back can read the editor text and flush edits to disk (the editor's
            # text_widget/_chunks/save API live on the loader, not the scroll).
            self._code_loader = loader
            self._code_widget.setParent(self.central_container)
            self.central_stack.addWidget(self._code_widget)

        field_map = {
            "help": getattr(self, "help_field", None),
            "readme": getattr(self, "readme_field", None),
            "notes": getattr(self, "notes_field", None),
            "code": getattr(self, "_code_widget", None),
        }

        if currently_checked:
            # Remember the tab active before this click, so returning from code
            # fullscreen restores both its content AND its checked state
            # (otherwise the previous tab shows unchecked — colour mismatch).
            self._pre_code_button = next(
                (b for b in self.buttons
                 if b.isCheckable() and b.isChecked() and b is not button), None)
            for b in self.buttons:
                if b is not button and b.isCheckable():
                    b.setChecked(False)

            # Code view takes over the whole loader: hide all chrome, show only
            # the editor and a Back button (much more room to read code).
            if name == "code":
                if getattr(self, "_code_widget", None) is not None:
                    self._enter_code_fullscreen()
                return

            target_widget = field_map.get(name)

            if target_widget is not None:
                text_attr = f"{name}_text"
                text = getattr(self, text_attr, "")

                try:
                    if text_attr =="readme_text":
                        if self.readme_format =="markdown":
                            target_widget.setMarkdown(text)
                        elif self.readme_format =="html":
                            target_widget.setHtml(text)
                        else:
                            target_widget.setPlainText(text)
                    else:
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

    def _enter_code_fullscreen(self):
        """Show the code editor across the whole loader — hide the top/bottom
        chrome (tab buttons, Install, run controls) and reveal only a Back button,
        so code analysis gets the full available height."""
        self._pre_code_widget = self.central_stack.currentWidget()
        self.central_stack.setCurrentWidget(self._code_widget)
        self._chrome_header.setVisible(False)
        self._chrome_footer.setVisible(False)
        self._code_back_btn.setVisible(True)
        # Snapshot the editor text so Back can tell whether the code was edited
        # (the editor saves asynchronously and preserves the file mtime, so an
        # mtime check can't detect a change — compare the text instead).
        loader = getattr(self, "_code_loader", None)
        self._code_text_on_enter = (
            loader.text_widget.toPlainText()
            if loader is not None and getattr(loader, "text_widget", None) is not None
            else None
        )

    def _exit_code_fullscreen(self):
        """Restore the normal script view from code-fullscreen mode."""
        self._chrome_header.setVisible(True)
        self._chrome_footer.setVisible(True)
        self._code_back_btn.setVisible(False)
        self.code_button.setChecked(False)
        # If the code was edited in the fullscreen editor, flush it to disk
        # synchronously (the editor saves on a background thread and preserves the
        # file mtime), then refresh the interpreter list so the "Missing Python
        # libraries" detection re-runs against the new contents, and refresh help.
        loader = getattr(self, "_code_loader", None)
        edited = (
            loader is not None
            and getattr(loader, "text_widget", None) is not None
            and loader.text_widget.toPlainText() != getattr(self, "_code_text_on_enter", None)
        )
        if edited:
            try:
                if getattr(loader, "save_timer", None) is not None:
                    loader.save_timer.stop()
                loader._save_current_chunk()        # merge editor text into chunks
                # Synchronous write so check_imports (which reads the file) sees the
                # new content immediately, without racing the async save thread.
                loader._write_chunks_to_disk(list(loader._chunks), loader._current_path)
            except Exception:
                logger.debug("failed to flush edited code before refresh", exc_info=True)
            try:
                self.file_mtime = os.path.getmtime(self.path)
                self.btn_refresh_interpreter.click()
                self.update_help()
            except Exception:
                logger.debug("failed to refresh interpreter after code edit", exc_info=True)
        # Re-check the tab that was active before fullscreen so its button state
        # matches the restored content.
        prev_btn = getattr(self, "_pre_code_button", None)
        if prev_btn is not None and prev_btn.isCheckable():
            prev_btn.setChecked(True)
        prev = getattr(self, "_pre_code_widget", None)
        try:
            self.central_stack.setCurrentWidget(prev if prev is not None else self.welcome_field)
        except Exception:
            self.central_stack.setCurrentWidget(self.welcome_field)

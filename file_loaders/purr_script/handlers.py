import os
import re

from PyQt6.QtWidgets import QPushButton

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
            self.update_docs()

        if name == "code" and not hasattr(self, "_code_widget"):
            from file_loaders.python_file import Python_file
            loader = Python_file()
            self._code_widget = loader.load_file(
                self.path,
                parent=self.controller,
                target_widget=None,
                threads_list=self.controller.threads
            )
            self._code_widget.setParent(self.central_container)
            self.central_stack.addWidget(self._code_widget)

        field_map = {
            "docs": getattr(self, "docs_field", None),
            "help": getattr(self, "help_field", None),
            "favorite": getattr(self, "favorite_field", None),
            "readme": getattr(self, "readme_field", None),
            "history": getattr(self, "history_field", None),
            "notes": getattr(self, "notes_field", None),
            "code": getattr(self, "_code_widget", None),
        }

        if currently_checked:
            for b in self.buttons:
                if b is not button and b.isCheckable():
                    b.setChecked(False)

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

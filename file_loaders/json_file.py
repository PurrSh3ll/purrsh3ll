import json

from PyQt6.QtWidgets import QCheckBox, QMessageBox, QApplication

from file_loaders.base_file_loader import BaseFileLoader

class Json_file(BaseFileLoader):

    def _extra_control_bar_widgets(self, control_bar_widget, control_bar_layout):
        self._auto_format_checkbox = QCheckBox("Format", parent=control_bar_widget)
        self._auto_format_checkbox.toggled.connect(self._on_auto_format_toggled)
        control_bar_layout.addWidget(self._auto_format_checkbox)

    def _on_auto_format_toggled(self, checked: bool):
        if checked:
            ok = self._apply_json_format()
            if not ok:
                self._auto_format_checkbox.blockSignals(True)
                self._auto_format_checkbox.setChecked(False)
                self._auto_format_checkbox.blockSignals(False)
        else:
            self._restore_json_original()

    def _apply_json_format(self) -> bool:
        try:
            current = self.text_widget.toPlainText()
        except Exception:
            return False

        if getattr(self.text_widget, "_is_currently_formatted", False):
            return True

        try:
            parsed = json.loads(current)
        except Exception as e:
            msg = QMessageBox(self.parent.widgets['execution_tabs'])
            msg.setStyleSheet(self._controller.messagebox_stylesheet)
            msg.setWindowTitle("Invalid JSON")
            msg.setText("Cannot format")
            msg.setInformativeText(str(e))
            msg.exec()
            return False

        if not hasattr(self.text_widget, "_orig_before_format") or self.text_widget._orig_before_format is None:
            self.text_widget._orig_before_format = current

        pretty = json.dumps(parsed, indent=4, ensure_ascii=False)
        try:
            v = self.text_widget.verticalScrollBar().value()
            h = self.text_widget.horizontalScrollBar().value()
        except Exception:
            v = h = 0

        self.text_widget.setPlainText(pretty)

        try:
            self.text_widget.verticalScrollBar().setValue(v)
            self.text_widget.horizontalScrollBar().setValue(h)
        except Exception:
            pass

        self.text_widget._is_currently_formatted = True
        return True

    def _restore_json_original(self):
        orig = getattr(self.text_widget, "_orig_before_format", None)
        if orig is None:
            self.text_widget._is_currently_formatted = False
            return
        try:
            v = self.text_widget.verticalScrollBar().value()
            h = self.text_widget.horizontalScrollBar().value()
        except Exception:
            v = h = 0
        self.text_widget.setPlainText(orig)
        try:
            self.text_widget.verticalScrollBar().setValue(v)
            self.text_widget.horizontalScrollBar().setValue(h)
        except Exception:
            pass
        self.text_widget._is_currently_formatted = False

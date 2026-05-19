import logging

from PyQt6.QtCore import QPropertyAnimation, QRect, QEasingCurve, QEvent, QPoint
from PyQt6.QtWidgets import QApplication

logger = logging.getLogger(__name__)

class PanelManagerMixin:

    def toggle_menu(self):
        self.widgets["menu_bar"].setVisible(True)
        self.widgets["menu_button"].setVisible(False)
        for panel_key in ("slide_panel", "mode_panel", "notes_panel", "chat_panel", "snippet_panel"):
            self._set_panel_position(panel_key)

    def center_welcome_text(self):
        tabs = self.widgets["execution_tabs"]
        self.widgets["welcome_tab_text"].setGeometry(0, 0, tabs.width(), tabs.height())

    def _set_panel_position(self, panel_key):
        panel = self.widgets[panel_key]
        main_window = self.widgets["main_window"]
        menu_bar = self.widgets["menu_bar"]
        h = main_window.height() - menu_bar.height()
        if panel.width() > main_window.width():
            panel.setGeometry(4, 0, main_window.width(), h)
        else:
            panel.setGeometry(main_window.width() - panel.width(), 0, panel.width(), h)

    def set_position_slide_panel(self):
        self._set_panel_position("slide_panel")

    def set_position_mode_panel(self):
        self._set_panel_position("mode_panel")

    def set_position_notes_panel(self):
        self._set_panel_position("notes_panel")

    def set_position_chat_panel(self):
        self._set_panel_position("chat_panel")

    def set_position_snippet_panel(self):
        self._set_panel_position("snippet_panel")

    def set_position_slide_button(self):
        slide_button = self.widgets["slide_button"]
        slide_panel = self.widgets["slide_panel"]
        main_window = self.widgets["main_window"]

        if self.slide_panel_visible:
            new_x = slide_panel.x() - slide_button.width() + 14
            new_y = (main_window.height() // 5)
            slide_button.move(new_x, new_y)
        else:
            new_x = main_window.width() - 18
            new_y = (main_window.height() // 5)
            slide_button.move(new_x, new_y)

    def set_position_mode_button(self):
        mode_button = self.widgets["mode_button"]
        slide_button = self.widgets["slide_button"]
        mode_panel = self.widgets["mode_panel"]
        main_window = self.widgets["main_window"]

        if self.mode_panel_visible:
            new_x = mode_panel.x() - mode_button.width() + 14
            new_y = slide_button.y() + mode_button.height()
            mode_button.move(new_x, new_y)
        else:
            new_x = main_window.width() - 18
            new_y = slide_button.y() + mode_button.height()
            mode_button.move(new_x, new_y)

    def set_position_notes_button(self):
        notes_button = self.widgets["notes_button"]
        slide_button = self.widgets["slide_button"]
        notes_panel = self.widgets["notes_panel"]
        main_window = self.widgets["main_window"]

        if self.notes_panel_visible:
            new_x = notes_panel.x() - notes_button.width() + 14
            new_y = slide_button.y() + (2 * notes_button.height())
            notes_button.move(new_x, new_y)
        else:
            new_x = main_window.width() - 18
            new_y = slide_button.y() + (2 * notes_button.height())
            notes_button.move(new_x, new_y)

    def set_position_chat_button(self):
        chat_button = self.widgets["chat_button"]
        slide_button = self.widgets["slide_button"]
        chat_panel = self.widgets["chat_panel"]
        main_window = self.widgets["main_window"]

        if self.chat_panel_visible:
            new_x = chat_panel.x() - chat_button.width() + 14
            new_y = slide_button.y() + (3 * chat_button.height())
            chat_button.move(new_x, new_y)
        else:
            new_x = main_window.width() - 18
            new_y = slide_button.y() + (3 * chat_button.height())
            chat_button.move(new_x, new_y)

    def set_position_snippet_button(self):
        snippet_button = self.widgets["snippet_button"]
        slide_button = self.widgets["slide_button"]
        snippet_panel = self.widgets["snippet_panel"]
        main_window = self.widgets["main_window"]

        if self.snippet_panel_visible:
            new_x = snippet_panel.x() - snippet_button.width() + 14
            new_y = slide_button.y() + (4 * snippet_button.height())
            snippet_button.move(new_x, new_y)
        else:
            new_x = main_window.width() - 18
            new_y = slide_button.y() + (4 * snippet_button.height())
            snippet_button.move(new_x, new_y)

    def set_position_active_profile_combo(self):
        combo = self.widgets.get("global_active_profile_combo")
        if combo is None:
            return
        main_window = self.widgets["main_window"]
        new_x = main_window.width() - combo.width() - 8
        new_y = main_window.height() - combo.height() - 2
        combo.move(new_x, new_y)

        voice_btn = self.widgets.get("voice_button")
        if voice_btn is not None:
            voice_btn.move(new_x - voice_btn.width() - 4, new_y)

        voice_popup = self.widgets.get("voice_popup")
        if voice_popup is not None and voice_popup.isVisible():
            voice_popup.adjustSize()
            px = main_window.width() - voice_popup.width() - 4
            py = main_window.height() - new_y - voice_popup.height() - 6
            voice_popup.move(px, py)

    def _toggle_panel(self, panel_key, button_key, visible_attr, icon_closed, button_y_fn, anim_prefix):
        button = self.widgets[button_key]
        panel = self.widgets[panel_key]
        main_window = self.widgets["main_window"]
        button.clearFocus()

        self.hide_side_buttons(button_key)

        panel_width = panel.width()
        panel_end_x = main_window.width() - panel_width
        panel_start_x = main_window.width()
        panel_height = main_window.height()

        button_y = button_y_fn()
        button_hidden_x = main_window.width() - 18
        button_visible_x = main_window.width() - panel_width - 7

        panel_anim = QPropertyAnimation(panel, b"geometry")
        panel_anim.setDuration(300)
        panel_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        button_anim = QPropertyAnimation(button, b"pos")
        button_anim.setDuration(300)
        button_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        is_visible = getattr(self, visible_attr)

        if is_visible:
            panel_anim.setStartValue(QRect(panel_end_x, 0, panel_width, panel_height))
            panel_anim.setEndValue(QRect(panel_start_x, 0, panel_width, panel_height))
            panel_anim.finished.connect(panel.hide)

            button_anim.setStartValue(QPoint(button_visible_x, button_y))
            button_anim.setEndValue(QPoint(button_hidden_x, button_y))

            button.setText(icon_closed)
        else:
            panel.show()
            panel_anim.setStartValue(QRect(panel_start_x, 0, panel_width, panel_height))
            panel_anim.setEndValue(QRect(panel_end_x, 0, panel_width, panel_height))

            button_anim.setStartValue(QPoint(button_hidden_x, button_y))
            button_anim.setEndValue(QPoint(button_visible_x, button_y))

            button.setText(">")
            try:
                panel_anim.finished.disconnect()
            except TypeError:
                pass

            button.raise_()

        panel_anim.start()
        button_anim.start()

        setattr(self, f"_{anim_prefix}_panel_anim", panel_anim)
        setattr(self, f"_{anim_prefix}_button_anim", button_anim)

        setattr(self, visible_attr, not is_visible)

        try:
            QApplication.sendEvent(button, QEvent(QEvent.Type.Leave))
        except Exception:
            pass

        QApplication.processEvents()

    def toggle_notes(self, obj_name):
        slide_button = self.widgets["slide_button"]
        notes_button = self.widgets["notes_button"]
        self._toggle_panel(
            panel_key="notes_panel",
            button_key="notes_button",
            visible_attr="notes_panel_visible",
            icon_closed="📝",
            button_y_fn=lambda: slide_button.y() + slide_button.height() + notes_button.height(),
            anim_prefix="notes",
        )

    def toggle_mode(self, obj_name):
        slide_button = self.widgets["slide_button"]
        self._toggle_panel(
            panel_key="mode_panel",
            button_key="mode_button",
            visible_attr="mode_panel_visible",
            icon_closed="🔧",
            button_y_fn=lambda: slide_button.y() + slide_button.height(),
            anim_prefix="mode",
        )

    def toggle_slide(self, obj_name):
        main_window = self.widgets["main_window"]
        self._toggle_panel(
            panel_key="slide_panel",
            button_key="slide_button",
            visible_attr="slide_panel_visible",
            icon_closed="👁️",
            button_y_fn=lambda: main_window.height() // 5,
            anim_prefix="slide",
        )

    def toggle_chat(self, obj_name):
        slide_button = self.widgets["slide_button"]
        chat_button = self.widgets["chat_button"]
        self._toggle_panel(
            panel_key="chat_panel",
            button_key="chat_button",
            visible_attr="chat_panel_visible",
            icon_closed="🤖",
            button_y_fn=lambda: slide_button.y() + (3 * chat_button.height()),
            anim_prefix="chat",
        )

    def toggle_snippets(self, obj_name):
        slide_button = self.widgets["slide_button"]
        snippet_button = self.widgets["snippet_button"]
        self._toggle_panel(
            panel_key="snippet_panel",
            button_key="snippet_button",
            visible_attr="snippet_panel_visible",
            icon_closed="✂️",
            button_y_fn=lambda: slide_button.y() + (4 * snippet_button.height()),
            anim_prefix="snippet",
        )

    def hide_side_buttons(self, button_name):
        if (self.slide_panel_visible or self.mode_panel_visible or
                self.notes_panel_visible or self.chat_panel_visible or
                self.snippet_panel_visible):
            for button in self.side_buttons:
                if button is not button_name:
                    self.widgets[button].show()
        else:
            for button in self.side_buttons:
                if button is not button_name:
                    self.widgets[button].hide()

    def add_observer_var(self):
        self.widgets["op_rows_panel"].create_row()

    def delete_all_observer_rows(self):
        keys_to_remove = [k for k in self.panel_widgets if k.startswith("observer_row_")]
        for key in keys_to_remove:
            widget = self.panel_widgets.pop(key, None)
            if widget:
                widget.deleteLater()

        rows_layout = self.widgets["op_rows_panel"].rows_layout
        while rows_layout.count():
            item = rows_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)
                widget.deleteLater()

        try:
            with open(self.observer_panel_state_path, "w", encoding="utf-8") as f:
                f.write("")
        except Exception as e:
            logger.warning("Failed to clear observer panel state file", exc_info=True)

    def open_slide_panel_options(self):
        self.widgets["slider_options_dialog"].update_dynamic_fields()
        self.widgets["slider_options_dialog"].exec()

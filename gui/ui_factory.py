from PyQt6.QtWidgets import QWidget
from core.controller import controller_instance
from gui.builders.main_layout_builder import build_main_layout
from gui.builders.side_panels_builder import build_side_panels
from gui.builders.chat_panel_builder import build_chat_panel
from gui.builders.menu_builder import build_menu

c = controller_instance

def create_main_widget(main_window):
    central_widget = QWidget(main_window)
    c.register_widget("central_widget", central_widget)

def set_ui(main_window):
    build_main_layout(main_window)
    build_side_panels(main_window)
    build_chat_panel(main_window)

def create_menu(main_window):
    build_menu(main_window)

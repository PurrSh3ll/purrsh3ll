from core.stylesheets.styles_containers import build_container_styles
from core.stylesheets.styles_buttons import build_button_styles
from core.stylesheets.styles_inputs import build_input_styles
from core.stylesheets.styles_menus import build_menu_styles
from core.stylesheets.styles_labels import build_label_styles
from core.stylesheets.styles_tree_tabs import build_tree_tab_styles
from core.stylesheets.styles_painter import build_painter_styles

def build_base_styles(bg, fg, bd, gl) -> dict:
    result = {}
    result.update(build_container_styles(bg, fg, bd, gl))
    result.update(build_button_styles(bg, fg, bd, gl))
    result.update(build_input_styles(bg, fg, bd, gl))
    result.update(build_menu_styles(bg, fg, bd, gl))
    result.update(build_label_styles(bg, fg, bd, gl))
    result.update(build_tree_tab_styles(bg, fg, bd, gl))
    result.update(build_painter_styles(bg, fg, bd, gl))
    return result

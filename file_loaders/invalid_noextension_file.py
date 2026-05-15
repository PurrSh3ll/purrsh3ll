from file_loaders.base_file_loader import BaseFileLoader
from file_loaders.viewer_widgets import CustomTextEdit

class Noextension_file(BaseFileLoader):
    def _create_text_widget(self):
        return CustomTextEdit(controller=self.parent, parent=self._loading_scroll)

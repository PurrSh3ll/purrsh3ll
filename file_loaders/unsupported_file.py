from pygments.lexers import guess_lexer_for_filename
from pygments.util import ClassNotFound

from file_loaders.base_file_loader import BaseFileLoader
from file_loaders.highlighters.pygments_highlighter import PygmentsHighlighter
from file_loaders.viewer_widgets import CustomTextEdit


class Unsupported_file(BaseFileLoader):
    def _create_text_widget(self):
        return CustomTextEdit(controller=self.parent, parent=self._loading_scroll)

    def _post_update_file_info(self, num_lines):
        try:
            if num_lines == 0 or num_lines > 1000:
                if hasattr(self, "syntax_highlighter") and self.syntax_highlighter is not None:
                    try:
                        self.parent.text_highlighters.remove(self.syntax_highlighter)
                    except Exception:
                        pass
                    self.syntax_highlighter = None
            else:
                if not hasattr(self, "syntax_highlighter") or self.syntax_highlighter is None:
                    try:
                        content = self.text_widget.toPlainText()
                        filename = self._current_path or ""
                        lexer = guess_lexer_for_filename(filename, content)
                        self.syntax_highlighter = PygmentsHighlighter(
                            self.text_widget.document(), self.parent, lexer
                        )
                        self.parent.text_highlighters.append(self.syntax_highlighter)
                    except (ClassNotFound, Exception):
                        self.syntax_highlighter = None
        except Exception:
            pass

    def _cleanup_highlighter(self):
        if hasattr(self, "syntax_highlighter") and self.syntax_highlighter is not None:
            try:
                self.parent.text_highlighters.remove(self.syntax_highlighter)
            except Exception:
                pass
            self.syntax_highlighter = None

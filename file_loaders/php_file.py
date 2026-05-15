from PyQt6.QtGui import QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

from file_loaders.base_file_loader import BaseFileLoader
from file_loaders.viewer_widgets import CustomUnsupportedLabel
from file_loaders.highlighters.php_highlighter import PhpHighlighter

class Php_file(BaseFileLoader):
    def _extra_layout_widgets(self, layout):
        self._unsupported_info_label = CustomUnsupportedLabel(
            "Syntax Highlighting Disabled for files above 1000 lines",
            parent=self._loading_scroll
        )
        self._unsupported_info_label.setEnabled(False)
        self._unsupported_info_label.setVisible(False)
        layout.addWidget(self._unsupported_info_label)

    def _post_update_file_info(self, num_lines):
        try:
            if num_lines == 0:
                pass
            elif num_lines > 1000:
                if hasattr(self, "syntax_highlighter") and self.syntax_highlighter is not None:
                    try:
                        self.parent.text_highlighters.remove(self.syntax_highlighter)
                    except Exception:
                        pass
                    self.syntax_highlighter = None
                self._unsupported_info_label.setVisible(True)
            else:
                if not hasattr(self, "syntax_highlighter") or self.syntax_highlighter is None:
                    self.syntax_highlighter = PhpHighlighter(self.text_widget.document(), self.parent)
                    self.parent.text_highlighters.append(self.syntax_highlighter)
                self._unsupported_info_label.setVisible(False)
        except Exception:
            pass

    def _cleanup_highlighter(self):
        if hasattr(self, "syntax_highlighter") and self.syntax_highlighter is not None:
            try:
                self.parent.text_highlighters.remove(self.syntax_highlighter)
            except Exception:
                pass
            self.syntax_highlighter = None

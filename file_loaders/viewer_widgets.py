import codecs

from PyQt6.QtWidgets import QWidget, QLabel, QPlainTextEdit, QTextEdit, QApplication
from PyQt6.QtCore import Qt, QSize, QEvent, QRect, pyqtSignal, QObject
from PyQt6.QtGui import (
    QFont, QFontMetrics, QBrush, QTextCharFormat, QColor, QPainter, QPen,
    QTextCursor
)

class Worker(QObject):
    finished = pyqtSignal(str, str)

    def __init__(self, file_path, chunk_size=256 * 1024, parent=None):
        super().__init__()
        self.file_path = file_path
        self.chunk_size = chunk_size
        self.parent = parent

    def run(self):
        try:
            chunks = []
            decoder = codecs.getincrementaldecoder("utf-8")()
            with open(self.file_path, "rb") as f:
                while True:
                    raw = f.read(self.chunk_size)
                    if not raw:
                        break
                    text = decoder.decode(raw, final=False)
                    if text:
                        chunks.append(text)
                tail = decoder.decode(b"", final=True)
                if tail:
                    chunks.append(tail)

            if self.parent is not None:
                if not hasattr(self.parent, "text_chunks"):
                    self.parent.text_chunks = {}
                self.parent.text_chunks[self.file_path] = chunks

            first_chunk = chunks[0] if chunks else ""
            self.finished.emit(self.file_path, first_chunk)

        except Exception as e:
            self.finished.emit(self.file_path, f"__ERROR__:{e}")

class LineNumberArea(QWidget):
    def __init__(self, editor):
        super().__init__(editor)
        self._editor = editor

    def sizeHint(self) -> QSize:
        return QSize(self._editor.lineNumberAreaWidth(), 0)

    def paintEvent(self, event):
        self._editor.lineNumberAreaPaintEvent(event)

class TextEditWithLineNumbers(QPlainTextEdit):
    lineCountChanged = pyqtSignal(int)

    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.parent = parent
        self._controller = controller
        self._lineNumberArea = LineNumberArea(self)
        self.setObjectName("text_edit_line_numb")
        self._init_painter_colors()

        font = QFont("Courier New")
        font.setPointSize(11)
        self.setFont(font)

        self._current_line_rect = None

        self.blockCountChanged.connect(self._on_block_count_changed)
        self.updateRequest.connect(self._on_update_request)
        self.cursorPositionChanged.connect(self._on_cursor_position_changed)
        self.cursorPositionChanged.connect(self.update_current_line_rect)
        self.cursorPositionChanged.connect(self.highlight_current_line)
        self.updateRequest.connect(lambda rect, dy: self.update_current_line_rect())

        try:
            self.viewport().installEventFilter(self)
        except Exception:
            pass

        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._on_block_count_changed(self.blockCount())
        self.update_current_line_rect()
        self.highlight_current_line()

    def wheelEvent(self, event):
        modifiers = QApplication.keyboardModifiers()
        if modifiers & Qt.KeyboardModifier.ControlModifier:
            delta = event.angleDelta().y()
            if delta > 0:
                self.zoomIn(1)
            elif delta < 0:
                self.zoomOut(1)
            event.accept()
            return
        super().wheelEvent(event)

    def update_current_line_rect(self):
        try:
            cursor = self.textCursor()
            block = cursor.block()
            if not block.isValid():
                self._current_line_rect = None
                self.viewport().update()
                return
            block_geom = self.blockBoundingGeometry(block)
            top_left = block_geom.topLeft() + self.contentOffset()
            height = int(self.blockBoundingRect(block).height())
            self._current_line_rect = QRect(0, int(top_left.y()), self.viewport().width(), height)
        except Exception:
            self._current_line_rect = None
        finally:
            try:
                self.viewport().update()
            except Exception:
                self.update()

    def eventFilter(self, obj, event):
        if obj is self.viewport() and event.type() == QEvent.Type.Paint:
            res = super().eventFilter(obj, event)
            self._draw_line_highlight_in_viewport()
            return res
        return super().eventFilter(obj, event)

    def _draw_line_highlight_in_viewport(self):
        if not self._current_line_rect:
            return
        try:
            painter = QPainter(self.viewport())
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            base = getattr(self, "painter_active_bg", QColor("#3C3F41"))
            col = QColor(base)
            if col.alpha() == 255:
                col.setAlpha(140)
            painter.fillRect(self._current_line_rect, col)
            painter.end()
        except Exception:
            pass

    def _init_painter_colors(self):
        q = getattr(self._controller, "qss_QPainter", {})
        self.painter_area = QColor(q.get("painter_area", "#2B2D30"))
        self.painter_text = QColor(q.get("painter_text", "#888888"))
        self.painter_text_active = QColor(q.get("painter_text_active", "#FFFFFF"))
        self.painter_active_bg = QColor(q.get("painter_active_bg", "#3C3F41"))
        self.painter_lines = QColor(q.get("painter_lines", "#2B2D30"))
        self.upper_border = q.get("painter_lines", "#2B2D30")
        self.setStyleSheet(
            f"border-top: 1px solid {self.upper_border}; border-bottom: none; border-left: none; border-right: none;"
        )

    def highlight_current_line(self):
        try:
            fmt = QTextCharFormat()
            bg = getattr(self, "painter_active_bg", None)
            if not isinstance(bg, QColor):
                bg = QColor("#FFFF00")
            fmt.setBackground(QBrush(bg))
            sel = QTextEdit.ExtraSelection()
            sel.format = fmt
            cursor = self.textCursor()
            cursor.select(QTextCursor.SelectionType.LineUnderCursor)
            sel.cursor = cursor
            self.setExtraSelections([sel])
            self.viewport().update()
        except Exception:
            try:
                self.setExtraSelections([])
            except Exception:
                pass

    def update_painter_colors(self, painter_area=None, painter_text=None,
                              painter_text_active=None, painter_active_bg=None, painter_lines=None):
        def _set_color(attr_name, value):
            if value is None:
                return
            cur = getattr(self, attr_name, None)
            if isinstance(value, str):
                if isinstance(cur, QColor):
                    cur.setNamedColor(value)
                else:
                    setattr(self, attr_name, QColor(value))
            elif isinstance(value, QColor):
                setattr(self, attr_name, value)

        if painter_area is None and painter_text is None and painter_text_active is None and painter_active_bg is None:
            q = getattr(self._controller, "qss_QPainter", {})
            self.setStyleSheet(
                f"border-top: 1px solid {q.get('painter_lines', None)}; border-bottom: none; border-left: none; border-right: none;"
            )
            painter_area = q.get("painter_area", None)
            painter_text = q.get("painter_text", None)
            painter_text_active = q.get("painter_text_active", None)
            painter_active_bg = q.get("painter_active_bg", None)
            painter_lines = q.get("painter_lines", None)

        _set_color("painter_area", painter_area)
        _set_color("painter_text", painter_text)
        _set_color("painter_text_active", painter_text_active)
        _set_color("painter_active_bg", painter_active_bg)
        _set_color("painter_lines", painter_lines)

        self.highlight_current_line()
        try:
            self._lineNumberArea.update()
            self.viewport().update()
        except Exception:
            self.update()

    def lineNumberAreaWidth(self):
        digits = max(1, len(str(max(1, self.blockCount()))))
        return 8 + self.fontMetrics().horizontalAdvance('9') * digits

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self._lineNumberArea.setGeometry(
            QRect(cr.left(), cr.top(), self.lineNumberAreaWidth(), cr.height())
        )

    def _on_block_count_changed(self, new_count):
        self.setViewportMargins(self.lineNumberAreaWidth(), 0, 0, 0)
        self._lineNumberArea.update()
        self.lineCountChanged.emit(new_count)

    def _on_update_request(self, rect, dy):
        if dy:
            self._lineNumberArea.scroll(0, dy)
        else:
            self._lineNumberArea.update(0, rect.y(), self._lineNumberArea.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self._on_block_count_changed(self.blockCount())

    def _on_cursor_position_changed(self):
        self._lineNumberArea.update()

    def lineNumberAreaPaintEvent(self, event):
        painter = QPainter(self._lineNumberArea)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        painter.fillRect(event.rect(), self.painter_area)

        border_pen = QPen(self.painter_lines)
        border_pen.setWidth(1)
        painter.setPen(border_pen)
        x = self._lineNumberArea.width() - 1
        painter.drawLine(x, event.rect().top(), x, event.rect().bottom())

        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = int(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + int(self.blockBoundingRect(block).height())

        base_font = self.font()
        bold_font = QFont(base_font)
        bold_font.setWeight(QFont.Weight.Bold)
        fm = QFontMetrics(base_font)
        line_height = fm.height()

        cursor_block_num = self.textCursor().blockNumber()

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                rect = QRect(0, top, self._lineNumberArea.width() - 4, line_height)
                if block_number == cursor_block_num:
                    painter.fillRect(0, top, self._lineNumberArea.width(), line_height, self.painter_active_bg)
                    painter.setPen(self.painter_text_active)
                    painter.setFont(bold_font)
                else:
                    painter.setPen(self.painter_text)
                    painter.setFont(base_font)
                painter.drawText(rect, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, number)
            block = block.next()
            top = bottom
            bottom = top + int(self.blockBoundingRect(block).height())
            block_number += 1

        painter.end()

class CustomTextEdit(QTextEdit):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller

    def update_painter_colors(self):
        line_color = self.controller.qss_QPainter.get("painter_lines")
        self.setStyleSheet(
            f"border-top: 2px solid {line_color}; border-bottom: none; border-left: none; border-right: none;"
        )

    def wheelEvent(self, event):
        modifiers = QApplication.keyboardModifiers()
        if modifiers & Qt.KeyboardModifier.ControlModifier:
            delta = event.angleDelta().y()
            if delta > 0:
                self.zoomIn(1)
            elif delta < 0:
                self.zoomOut(1)
            event.accept()
            return
        super().wheelEvent(event)

class CustomUnsupportedLabel(QLabel):
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setObjectName("unsupported_info_label")
        self.setText(text)

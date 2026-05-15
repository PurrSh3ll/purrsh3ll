from PyQt6.QtWidgets import QStyledItemDelegate
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QTextDocument, QTextOption

class WrapAnywhereDelegate(QStyledItemDelegate):
    def __init__(self, parent=None):
        super().__init__(parent)

    def paint(self, painter, option, index):
        text = index.data(Qt.ItemDataRole.DisplayRole) or ""
        doc = QTextDocument()
        doc.setDefaultFont(option.font)
        opt = QTextOption()
        opt.setWrapMode(QTextOption.WrapMode.WrapAnywhere)
        doc.setDefaultTextOption(opt)
        doc.setPlainText(str(text))
        doc.setTextWidth(option.rect.width())

        painter.save()
        doc_height = doc.size().height()
        y_offset = 0
        if option.displayAlignment & Qt.AlignmentFlag.AlignVCenter and doc_height < option.rect.height():
            y_offset = (option.rect.height() - doc_height) / 2
        painter.translate(option.rect.topLeft().x(), option.rect.topLeft().y() + y_offset)
        painter.setClipRect(0, 0, option.rect.width(), option.rect.height())
        doc.drawContents(painter)
        painter.restore()

    def sizeHint(self, option, index):
        text = index.data(Qt.ItemDataRole.DisplayRole) or ""
        doc = QTextDocument()
        doc.setDefaultFont(option.font)
        opt = QTextOption()
        opt.setWrapMode(QTextOption.WrapMode.WrapAnywhere)
        doc.setDefaultTextOption(opt)
        doc.setPlainText(str(text))
        width = option.rect.width() if option.rect.width() > 0 else 200
        doc.setTextWidth(width)
        size = doc.size().toSize()
        return QSize(size.width(), size.height())

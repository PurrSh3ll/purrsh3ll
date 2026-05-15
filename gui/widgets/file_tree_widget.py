import os
import shutil

from PyQt6.QtWidgets import QTreeWidget, QAbstractItemView, QMessageBox
from PyQt6.QtCore import Qt, QEvent

from core.controller import controller_instance


class FileTreeWidget(QTreeWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.c = controller_instance
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setDefaultDropAction(Qt.DropAction.MoveAction)

    def _is_top_appmodule(self, path):
        if not path or path == "__separator__":
            return False
        app_modules = getattr(self.c, "app_modules_path", None)
        if not app_modules:
            return False
        return (
            path.startswith(app_modules) and
            os.path.dirname(os.path.normpath(path)) == os.path.normpath(app_modules)
        )

    def keyPressEvent(self, event):
        key = event.key()
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            if hasattr(self.c, "on_enter_pressed"):
                self.c.on_enter_pressed()
            event.accept()
            return
        if key == Qt.Key.Key_Delete:
            self._handle_delete_key()
            event.accept()
            return
        super().keyPressEvent(event)

    def _handle_delete_key(self):
        item = self.currentItem()
        if item is None:
            return
        path = item.data(0, Qt.ItemDataRole.UserRole)
        if not path or path == "__separator__":
            return
        if self._is_top_appmodule(path):
            return
        name = os.path.basename(path)
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f'Are you sure you want to delete "{name}"?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
        except Exception as e:
            QMessageBox.critical(self, "Delete Failed", str(e))

    def startDrag(self, supportedActions):
        item = self.currentItem()
        if item is None:
            return
        path = item.data(0, Qt.ItemDataRole.UserRole)
        if not path or path == "__separator__":
            return
        if self._is_top_appmodule(path):
            return
        super().startDrag(supportedActions)

    def dragEnterEvent(self, event):
        if event.source() is self:
            event.accept()
        else:
            event.ignore()

    def _is_appmodules_root(self, dest_dir):
        app_modules = getattr(self.c, "app_modules_path", None)
        if not app_modules:
            return False
        return os.path.normpath(dest_dir) == os.path.normpath(app_modules)

    def dragMoveEvent(self, event):
        if event.source() is not self:
            event.ignore()
            return

        target_item = self.itemAt(event.position().toPoint())
        if target_item is not None:
            target_path = target_item.data(0, Qt.ItemDataRole.UserRole)
            if target_path == "__separator__":
                event.ignore()
                return

        # Wywołaj super() najpierw — aktualizuje dropIndicatorPosition()
        super().dragMoveEvent(event)

        if target_item is not None:
            target_path = target_item.data(0, Qt.ItemDataRole.UserRole)
            indicator = self.dropIndicatorPosition()
            if (
                indicator == QAbstractItemView.DropIndicatorPosition.OnItem
                and os.path.isdir(target_path)
            ):
                candidate_dir = target_path
            else:
                candidate_dir = os.path.dirname(os.path.normpath(target_path))
            if self._is_appmodules_root(candidate_dir):
                event.ignore()

    def dropEvent(self, event):
        if event.source() is not self:
            event.ignore()
            return

        dragged_item = self.currentItem()
        if dragged_item is None:
            event.ignore()
            return

        src_path = dragged_item.data(0, Qt.ItemDataRole.UserRole)
        if not src_path or src_path == "__separator__":
            event.ignore()
            return

        if self._is_top_appmodule(src_path):
            event.ignore()
            return

        target_item = self.itemAt(event.position().toPoint())
        if target_item is None:
            event.ignore()
            return

        target_path = target_item.data(0, Qt.ItemDataRole.UserRole)
        if not target_path or target_path == "__separator__":
            event.ignore()
            return

        indicator = self.dropIndicatorPosition()
        if (
            indicator == QAbstractItemView.DropIndicatorPosition.OnItem
            and os.path.isdir(target_path)
        ):
            dest_dir = target_path
        else:
            dest_dir = os.path.dirname(os.path.normpath(target_path))

        src_norm = os.path.normpath(src_path)
        dest_norm = os.path.normpath(dest_dir)

        # Nie przesuwaj do głównego folderu appmodules
        if self._is_appmodules_root(dest_dir):
            event.ignore()
            return

        # Nie przesuwaj do siebie
        if src_norm == dest_norm:
            event.ignore()
            return

        # Nie przesuwaj folderu do jego własnego podfolderu
        if os.path.isdir(src_path) and dest_norm.startswith(src_norm + os.sep):
            event.ignore()
            return

        dest_path = os.path.join(dest_dir, os.path.basename(src_path))

        if os.path.normpath(dest_path) == src_norm:
            event.ignore()
            return

        if os.path.exists(dest_path):
            QMessageBox.warning(
                self,
                "Move Failed",
                f'"{os.path.basename(src_path)}" already exists in this location.',
            )
            event.ignore()
            return

        try:
            shutil.move(src_path, dest_path)
        except Exception as e:
            QMessageBox.critical(self, "Move Failed", str(e))

        # Nie wywołuj super().dropEvent — watcher odświeży drzewo
        event.accept()
